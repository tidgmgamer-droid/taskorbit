package com.taskorbit.secure

import android.Manifest
import android.app.AlarmManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.room.*
import androidx.room.migration.Migration
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.*

// Model names change. If Gemini stops answering, check the current name in Google AI Studio
// and paste it into Settings. It is editable in the app.
const val DEFAULT_MODEL = "gemini-3.7-flash"

private val BG = Color(0xFF090D16)
private val SURFACE = Color(0xFF131B2E)
private val SURFACE2 = Color(0xFF1E293B)
private val GREEN = Color(0xFF10B981)
private val AMBER = Color(0xFFF59E0B)
private val RED = Color(0xFFEF4444)
private val MUTED = Color(0xFF94A3B8)

private val CATEGORIES = listOf("Study", "Work", "Health", "Personal", "Other")

// ---------------------------------------------------------------------------
// 1. DATA: encrypted database
// ---------------------------------------------------------------------------

enum class Horizon { TODAY, WEEK, MONTH }

enum class Priority(val weight: Int, val label: String) {
    HIGH(3, "HIGH"), MEDIUM(2, "MED"), LOW(1, "LOW")
}

@Entity(tableName = "tasks")
data class TaskEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val title: String,
    val horizon: Horizon,
    val priority: Priority,
    val category: String = "Study",
    val status: String = "PENDING",
    val failReason: String? = null,
    val deferCount: Int = 0,
    val createdAt: Long = System.currentTimeMillis(),
    val completedHour: Int? = null,
    val dayOfWeekCompleted: Int? = null,
    val monthKey: String = "",
    val periodKey: String = "",
    val completedAt: Long? = null
)

@Dao
interface TaskDao {
    @Query("SELECT * FROM tasks ORDER BY createdAt DESC")
    fun observeAllTasks(): Flow<List<TaskEntity>>

    @Query("SELECT * FROM tasks")
    suspend fun getAllTasksSync(): List<TaskEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertTask(task: TaskEntity): Long

    @Update
    suspend fun updateTask(task: TaskEntity)

    @Delete
    suspend fun deleteTask(task: TaskEntity)
}

val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE tasks ADD COLUMN periodKey TEXT NOT NULL DEFAULT ''")
        db.execSQL("ALTER TABLE tasks ADD COLUMN completedAt INTEGER")
    }
}

object SecureStore {
    @Volatile private var cached: SharedPreferences? = null

    fun prefs(context: Context): SharedPreferences {
        return cached ?: synchronized(this) {
            cached ?: run {
                val app = context.applicationContext
                val masterKey = MasterKey.Builder(app)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
                val created = EncryptedSharedPreferences.create(
                    app, "taskorbit_keystore_prefs", masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )
                cached = created
                created
            }
        }
    }
}

@Database(entities = [TaskEntity::class], version = 2, exportSchema = false)
abstract class EncryptedVaultDatabase : RoomDatabase() {
    abstract fun taskDao(): TaskDao

    companion object {
        @Volatile private var INSTANCE: EncryptedVaultDatabase? = null

        fun getInstance(context: Context): EncryptedVaultDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: build(context.applicationContext).also { INSTANCE = it }
            }
        }

        private fun build(context: Context): EncryptedVaultDatabase {
            System.loadLibrary("sqlcipher")
            val factory = SupportOpenHelperFactory(getOrCreateKey(context))
            return Room.databaseBuilder(
                context,
                EncryptedVaultDatabase::class.java,
                "taskorbit_aes256_vault.db"
            ).openHelperFactory(factory)
                .addMigrations(MIGRATION_1_2)
                .build()
        }

        private fun getOrCreateKey(context: Context): ByteArray {
            val prefs = SecureStore.prefs(context)
            val existing = prefs.getString("db_aes_key", null)
            if (existing != null) return Base64.getDecoder().decode(existing)
            val bytes = ByteArray(32)
            SecureRandom().nextBytes(bytes)
            // commit() on purpose: losing this key would make the database unreadable
            prefs.edit().putString("db_aes_key", Base64.getEncoder().encodeToString(bytes)).commit()
            return bytes
        }
    }
}

// ---------------------------------------------------------------------------
// 2. DATES, DAILY RESET, STREAK
// ---------------------------------------------------------------------------

object Keys {
    private fun fmt(pattern: String, t: Long): String =
        SimpleDateFormat(pattern, Locale.US).format(Date(t))

    fun day(t: Long = System.currentTimeMillis()): String = fmt("yyyy-MM-dd", t)
    fun week(t: Long = System.currentTimeMillis()): String = fmt("YYYY-'W'ww", t)
    fun month(t: Long = System.currentTimeMillis()): String = fmt("yyyy-MM", t)

    fun forHorizon(h: Horizon): String = when (h) {
        Horizon.TODAY -> day()
        Horizon.WEEK -> week()
        Horizon.MONTH -> month()
    }

    fun prevMonth(): String {
        val c = Calendar.getInstance()
        c.set(Calendar.DAY_OF_MONTH, 1)
        c.add(Calendar.MONTH, -1)
        return month(c.timeInMillis)
    }

    fun monthLabel(key: String): String {
        return try {
            val d = SimpleDateFormat("yyyy-MM", Locale.US).parse(key)
            SimpleDateFormat("MMMM yyyy", Locale.US).format(d!!)
        } catch (e: Exception) {
            key
        }
    }
}

object Rollover {
    // Unfinished tasks move into the current day/week/month and count as one more postponement.
    // Finished and skipped tasks stay in the period they belong to.
    suspend fun rollForward(db: EncryptedVaultDatabase) {
        val dao = db.taskDao()
        for (t in dao.getAllTasksSync()) {
            val key = Keys.forHorizon(t.horizon)
            if (t.status == "PENDING" && t.periodKey != key) {
                val bump = if (t.periodKey.isEmpty()) 0 else 1
                dao.updateTask(t.copy(periodKey = key, deferCount = t.deferCount + bump))
            }
        }
    }
}

fun currentStreak(tasks: List<TaskEntity>): Int {
    val days = tasks.mapNotNull { it.completedAt }.map { Keys.day(it) }.toSet()
    val c = Calendar.getInstance()
    if (Keys.day(c.timeInMillis) !in days) c.add(Calendar.DAY_OF_YEAR, -1)
    var n = 0
    while (Keys.day(c.timeInMillis) in days) {
        n++
        c.add(Calendar.DAY_OF_YEAR, -1)
    }
    return n
}

// ---------------------------------------------------------------------------
// 3. COACH: on-phone quick read, AI prompt, Gemini, sharing, export
// ---------------------------------------------------------------------------

object LocalCoach {
    fun bullets(tasks: List<TaskEntity>): List<String> {
        if (tasks.isEmpty()) return listOf("No tasks in this period yet. Add a few and check back.")
        val out = mutableListOf<String>()

        val done = tasks.count { it.status == "DONE" }
        val failed = tasks.count { it.status == "FAILED" }
        val open = tasks.count { it.status == "PENDING" }
        out.add("Finished $done of ${tasks.size} tasks (${done * 100 / tasks.size}%). $failed skipped, $open still open.")

        val high = tasks.filter { it.priority == Priority.HIGH }
        val rest = tasks.filter { it.priority != Priority.HIGH }
        if (high.isNotEmpty() && rest.isNotEmpty()) {
            val hr = high.count { it.status == "DONE" } * 100 / high.size
            val rr = rest.count { it.status == "DONE" } * 100 / rest.size
            if (hr + 20 <= rr) {
                out.add("High priority: $hr% done vs $rr% for the easier ones. You are clearing easy work and dodging the important stuff. Do one High task first thing tomorrow.")
            } else if (hr >= 60) {
                out.add("High priority tasks are getting done ($hr%). Keep doing them first.")
            }
        }

        val stuck = tasks.filter { it.deferCount >= 2 && it.status == "PENDING" }
            .maxByOrNull { it.deferCount }
        if (stuck != null) {
            out.add("\"${stuck.title}\" has been pushed back ${stuck.deferCount} times. Cut it down to a 10 minute first step, or drop it.")
        }

        val failedTasks = tasks.filter { it.status == "FAILED" }
        if (failedTasks.isNotEmpty()) {
            val top = failedTasks.groupingBy { it.failReason ?: "Unspecified" }
                .eachCount().maxByOrNull { it.value }!!
            val pct = top.value * 100 / failedTasks.size
            val fix = when (top.key) {
                "Lack of time" -> "Cap yourself at 3 tasks a day (1 High, 1 Medium, 1 Low)."
                "Too difficult / Blocker" -> "Before a hard task, spend 20 minutes working out only the first step."
                "Low energy" -> "Move your High priority work to the morning."
                "Procrastinated" -> "Use a 2 minute rule: open it, work 2 minutes, then decide."
                else -> "Next time you skip something, write down what got in the way."
            }
            out.add("Main reason tasks get skipped: ${top.key} ($pct% of skips). $fix")
        }

        val hours = tasks.mapNotNull { it.completedHour }
        if (hours.size >= 3) {
            val best = hours.groupingBy { it }.eachCount().maxByOrNull { it.value }!!.key
            out.add("You finish the most tasks around $best:00. Put your hardest task near that time.")
        }
        return out
    }
}

object PromptBuilder {
    private val dayNames = listOf("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")

    fun build(tasks: List<TaskEntity>, label: String, includeTitles: Boolean): String {
        val sb = StringBuilder()
        sb.appendLine("You are a direct, practical productivity coach. Below is my task data for $label from my to-do app.")
        sb.appendLine("Reply with 5 to 7 short bullet points, each starting with the \"•\" character. No headers, no markdown, no bold text. Cover what went well, the biggest pattern holding me back, one concrete rule to try next, and end with one question for me. Be honest, not flattering.")
        sb.appendLine()

        val done = tasks.count { it.status == "DONE" }
        val failed = tasks.count { it.status == "FAILED" }
        val open = tasks.count { it.status == "PENDING" }
        sb.appendLine("Totals: ${tasks.size} tasks, $done done, $failed skipped, $open still open.")

        Priority.entries.forEach { p ->
            val group = tasks.filter { it.priority == p }
            if (group.isNotEmpty()) {
                sb.appendLine("${p.label} priority: ${group.count { it.status == "DONE" }} of ${group.size} done")
            }
        }
        tasks.groupBy { it.category }.forEach { (c, g) ->
            sb.appendLine("Category $c: ${g.count { it.status == "DONE" }} of ${g.size} done")
        }
        val reasons = tasks.filter { it.status == "FAILED" }
            .groupingBy { it.failReason ?: "Unspecified" }.eachCount()
        if (reasons.isNotEmpty()) {
            sb.appendLine("Skip reasons: " + reasons.entries.joinToString(", ") { "${it.key} x${it.value}" })
        }
        sb.appendLine("Tasks postponed at least once: ${tasks.count { it.deferCount > 0 }}. Most postponed: ${tasks.maxOfOrNull { it.deferCount } ?: 0} times.")

        val hours = tasks.mapNotNull { it.completedHour }
        if (hours.isNotEmpty()) sb.appendLine("Hours of the day tasks were finished: " + hours.sorted().joinToString(", "))
        val days = tasks.mapNotNull { it.dayOfWeekCompleted }
        if (days.isNotEmpty()) {
            sb.appendLine("Weekdays tasks were finished: " + days.joinToString(", ") { dayNames[(it - 1).coerceIn(0, 6)] })
        }

        if (includeTitles) {
            sb.appendLine()
            sb.appendLine("Task list:")
            tasks.forEach {
                val late = if (it.deferCount > 0) " (postponed ${it.deferCount}x)" else ""
                sb.appendLine("- [${it.status}] ${it.priority.label} ${it.category}: ${it.title}$late")
            }
        }
        return sb.toString().trim()
    }
}

object GeminiClient {
    fun ask(apiKey: String, model: String, prompt: String): Result<String> = runCatching {
        val conn = URL("https://generativelanguage.googleapis.com/v1beta/models/$model:generateContent")
            .openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = 15000
            conn.readTimeout = 60000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("x-goog-api-key", apiKey)

            val part = JSONObject().put("text", prompt)
            val content = JSONObject().put("parts", JSONArray().put(part))
            val body = JSONObject().put("contents", JSONArray().put(content)).toString()
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }

            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val raw = stream?.bufferedReader()?.use { it.readText() } ?: ""
            if (code !in 200..299) {
                val msg = try {
                    JSONObject(raw).getJSONObject("error").getString("message")
                } catch (e: Exception) {
                    raw.take(200)
                }
                throw IllegalStateException("Gemini said ($code): $msg")
            }
            val candidates = JSONObject(raw).optJSONArray("candidates")
            if (candidates == null || candidates.length() == 0) {
                throw IllegalStateException("Gemini returned no answer. Try again, or check the model name in Settings.")
            }
            candidates.getJSONObject(0).getJSONObject("content")
                .getJSONArray("parts").getJSONObject(0).getString("text")
        } finally {
            conn.disconnect()
        }
    }
}

fun cleanAi(raw: String): String {
    return raw.replace("**", "").lines().joinToString("\n") { line ->
        val t = line.trim()
        if (t.startsWith("* ")) "• " + t.removePrefix("* ") else line.trimEnd()
    }.trim()
}

fun shareText(context: Context, text: String) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    context.startActivity(Intent.createChooser(send, "Open in your AI app"))
}

fun copyText(context: Context, text: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("TaskOrbit", text))
    Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
}

private fun csvQuote(s: String): String = "\"" + s.replace("\"", "\"\"") + "\""

fun tasksToCsv(tasks: List<TaskEntity>): String {
    val sb = StringBuilder("title,horizon,priority,category,status,fail_reason,postponed,created,completed_hour\n")
    tasks.sortedBy { it.createdAt }.forEach { t ->
        sb.append(csvQuote(t.title)).append(',')
            .append(t.horizon.name).append(',')
            .append(t.priority.name).append(',')
            .append(csvQuote(t.category)).append(',')
            .append(t.status).append(',')
            .append(csvQuote(t.failReason ?: "")).append(',')
            .append(t.deferCount).append(',')
            .append(Keys.day(t.createdAt)).append(',')
            .append(t.completedHour?.toString() ?: "")
            .append('\n')
    }
    return sb.toString()
}

// ---------------------------------------------------------------------------
// 4. LAUNCHER ICON MOOD + 8 AM ALARM
// ---------------------------------------------------------------------------

enum class IconMood(val aliasName: String) {
    HAPPY("com.taskorbit.secure.LauncherIconHappy"),
    PENDING("com.taskorbit.secure.LauncherIconPending"),
    DANGER("com.taskorbit.secure.LauncherIconDanger")
}

object IconSwitcher {
    fun moodFor(todayTasks: List<TaskEntity>): IconMood {
        val done = todayTasks.count { it.status == "DONE" }
        val failed = todayTasks.count { it.status == "FAILED" }
        val pending = todayTasks.count { it.status == "PENDING" }
        val hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)
        return when {
            todayTasks.isNotEmpty() && pending == 0 && done > 0 && failed == 0 -> IconMood.HAPPY
            failed > 0 || (pending > 0 && hour >= 20) -> IconMood.DANGER
            else -> IconMood.PENDING
        }
    }

    // Called when the app goes to the background or from the alarm, never while the screen is drawing.
    fun apply(context: Context, mood: IconMood) {
        val pm = context.packageManager
        val target = ComponentName(context.packageName, mood.aliasName)
        if (pm.getComponentEnabledSetting(target) != PackageManager.COMPONENT_ENABLED_STATE_ENABLED) {
            pm.setComponentEnabledSetting(target, PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
        }
        IconMood.entries.filter { it != mood }.forEach { m ->
            val comp = ComponentName(context.packageName, m.aliasName)
            if (pm.getComponentEnabledSetting(comp) != PackageManager.COMPONENT_ENABLED_STATE_DISABLED) {
                pm.setComponentEnabledSetting(comp, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
            }
        }
    }
}

class MorningAndMonthlyReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val app = context.applicationContext
        scheduleMorningAlarm(app, 8, 0)
        // After a reboot we only re-arm the alarm. No notification at a random hour.
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) return

        val result = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val db = EncryptedVaultDatabase.getInstance(app)
                Rollover.rollForward(db)
                val all = db.taskDao().getAllTasksSync()
                val today = all.filter { it.horizon == Horizon.TODAY && it.periodKey == Keys.day() }
                IconSwitcher.apply(app, IconSwitcher.moodFor(today))

                val prev = Keys.prevMonth()
                val prefs = SecureStore.prefs(app)
                val reportDue = !prefs.getBoolean("notified_$prev", false) && all.any { it.monthKey == prev }
                if (reportDue) prefs.edit().putBoolean("notified_$prev", true).apply()

                sendNotification(app, today.count { it.status == "PENDING" }, if (reportDue) prev else null)
            } catch (e: Exception) {
                // nothing useful to do in a background receiver
            } finally {
                result?.finish()
            }
        }
    }

    private fun sendNotification(context: Context, pendingToday: Int, reportMonth: String?) {
        val channelId = "taskorbit_morning_brief"
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(channelId, "Morning plan", NotificationManager.IMPORTANCE_HIGH)
            )
        }
        val open = Intent(context, MainActivity::class.java)
        if (reportMonth != null) open.putExtra("open_coach_last_month", true)
        val tap = PendingIntent.getActivity(
            context, 0, open,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val title: String
        val text: String
        if (reportMonth != null) {
            title = "Your ${Keys.monthLabel(reportMonth)} report is ready"
            text = "Tap to see how the month went and what to change."
        } else {
            title = "TaskOrbit morning plan"
            text = if (pendingToday > 0) {
                "$pendingToday task(s) waiting for today. Pick what you will finish."
            } else {
                "Nothing planned for today yet. Tap to add your tasks."
            }
        }
        val notif = NotificationCompat.Builder(context, channelId)
            .setSmallIcon(android.R.drawable.ic_popup_reminder)
            .setContentTitle(title)
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(tap)
            .setAutoCancel(true)
            .build()
        nm.notify(101, notif)
    }

    companion object {
        fun scheduleMorningAlarm(context: Context, hour: Int, minute: Int) {
            val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            val intent = Intent(context, MorningAndMonthlyReceiver::class.java).apply {
                action = "com.taskorbit.secure.ACTION_MORNING_PROMPT"
            }
            val pi = PendingIntent.getBroadcast(
                context, 800, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val cal = Calendar.getInstance().apply {
                set(Calendar.HOUR_OF_DAY, hour)
                set(Calendar.MINUTE, minute)
                set(Calendar.SECOND, 0)
                if (timeInMillis <= System.currentTimeMillis()) add(Calendar.DAY_OF_YEAR, 1)
            }
            try {
                am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, cal.timeInMillis, pi)
            } catch (e: Exception) {
                // alarm could not be set; the app will try again next time it opens
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 5. SMART HORIZON DETECTOR
// ---------------------------------------------------------------------------

data class HorizonDetectionResult(val detectedHorizon: Horizon, val showCautionWarning: Boolean)

object SmartHorizonDetector {
    private val monthRegex = Regex("\\b(this month|next month|month|monthly|eom|end of month)\\b", RegexOption.IGNORE_CASE)
    private val weekRegex = Regex("\\b(this week|next week|week|weekly|weekend|by (monday|tuesday|wednesday|thursday|friday|saturday|sunday))\\b", RegexOption.IGNORE_CASE)
    private val todayRegex = Regex("\\b(today|tonight|morning|evening|afternoon|now)\\b", RegexOption.IGNORE_CASE)

    fun classify(input: String, defaultHorizon: Horizon): HorizonDetectionResult {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return HorizonDetectionResult(defaultHorizon, false)
        if (monthRegex.containsMatchIn(trimmed)) return HorizonDetectionResult(Horizon.MONTH, false)
        if (weekRegex.containsMatchIn(trimmed)) return HorizonDetectionResult(Horizon.WEEK, false)
        if (todayRegex.containsMatchIn(trimmed)) return HorizonDetectionResult(Horizon.TODAY, false)
        return HorizonDetectionResult(defaultHorizon, true)
    }
}

// ---------------------------------------------------------------------------
// 6. ACTIVITY
// ---------------------------------------------------------------------------

enum class AppTab { TASKS, COACH, SETTINGS }

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        MorningAndMonthlyReceiver.scheduleMorningAlarm(this, 8, 0)
        val fromReport = intent?.getBooleanExtra("open_coach_last_month", false) ?: false
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(background = BG, surface = SURFACE, primary = GREEN)
            ) {
                TaskOrbitApp(startOnCoach = fromReport)
            }
        }
    }

    override fun onStart() {
        super.onStart()
        val app = applicationContext
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Rollover.rollForward(EncryptedVaultDatabase.getInstance(app))
            } catch (e: Exception) {
            }
        }
    }

    override fun onStop() {
        super.onStop()
        val app = applicationContext
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val all = EncryptedVaultDatabase.getInstance(app).taskDao().getAllTasksSync()
                val today = all.filter { it.horizon == Horizon.TODAY && it.periodKey == Keys.day() }
                IconSwitcher.apply(app, IconSwitcher.moodFor(today))
            } catch (e: Exception) {
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 7. UI
// ---------------------------------------------------------------------------

@Composable
fun TaskOrbitApp(startOnCoach: Boolean) {
    val context = LocalContext.current
    val db = remember { EncryptedVaultDatabase.getInstance(context) }
    val tasksFlow = remember { db.taskDao().observeAllTasks() }
    val tasks by tasksFlow.collectAsState(initial = emptyList())
    var tab by remember { mutableStateOf(if (startOnCoach) AppTab.COACH else AppTab.TASKS) }

    val notifLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    val todayTasks = tasks.filter { it.horizon == Horizon.TODAY && it.periodKey == Keys.day() }
    val mood = IconSwitcher.moodFor(todayTasks)
    val streak = remember(tasks) { currentStreak(tasks) }

    Scaffold(
        containerColor = BG,
        bottomBar = {
            NavigationBar(containerColor = SURFACE) {
                NavigationBarItem(
                    selected = tab == AppTab.TASKS,
                    onClick = { tab = AppTab.TASKS },
                    icon = { Icon(Icons.Default.CheckCircle, contentDescription = null) },
                    label = { Text("Tasks") }
                )
                NavigationBarItem(
                    selected = tab == AppTab.COACH,
                    onClick = { tab = AppTab.COACH },
                    icon = { Icon(Icons.Default.Star, contentDescription = null) },
                    label = { Text("Coach") }
                )
                NavigationBarItem(
                    selected = tab == AppTab.SETTINGS,
                    onClick = { tab = AppTab.SETTINGS },
                    icon = { Icon(Icons.Default.Settings, contentDescription = null) },
                    label = { Text("Settings") }
                )
            }
        }
    ) { pad ->
        Column(modifier = Modifier.fillMaxSize().padding(pad).padding(horizontal = 16.dp)) {
            Header(mood, streak)
            when (tab) {
                AppTab.TASKS -> TasksScreen(tasks, db)
                AppTab.COACH -> CoachScreen(tasks, startOnCoach)
                AppTab.SETTINGS -> SettingsScreen(tasks)
            }
        }
    }
}

@Composable
fun Header(mood: IconMood, streak: Int) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(
                    when (mood) {
                        IconMood.HAPPY -> GREEN
                        IconMood.PENDING -> AMBER
                        IconMood.DANGER -> RED
                    }
                ),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = when (mood) {
                    IconMood.HAPPY -> "🦉"
                    IconMood.PENDING -> "👀"
                    IconMood.DANGER -> "🔥"
                },
                fontSize = 20.sp
            )
        }
        Spacer(Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text("TaskOrbit", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp)
            Text("Encrypted on this phone", color = GREEN, fontSize = 10.sp)
        }
        if (streak > 0) {
            Text("🔥 $streak day streak", color = AMBER, fontWeight = FontWeight.Bold, fontSize = 12.sp)
        }
    }
}

@Composable
fun Panel(content: @Composable ColumnScope.() -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = SURFACE),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            content = content
        )
    }
}

@Composable
fun SectionTitle(text: String) {
    Text(text, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 15.sp)
}

@Composable
fun SwitchRow(label: String, sub: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label, color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
            Text(sub, color = MUTED, fontSize = 11.sp)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

// ----- Tasks tab -----

@Composable
fun TasksScreen(tasks: List<TaskEntity>, db: EncryptedVaultDatabase) {
    val scope = rememberCoroutineScope()
    val dao = db.taskDao()
    var horizon by remember { mutableStateOf(Horizon.TODAY) }
    var showAdd by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf<TaskEntity?>(null) }
    var failing by remember { mutableStateOf<TaskEntity?>(null) }

    val key = Keys.forHorizon(horizon)
    val visible = tasks
        .filter { it.horizon == horizon && (it.status == "PENDING" || it.periodKey == key) }
        .sortedWith(
            compareBy<TaskEntity> { it.status != "PENDING" }
                .thenByDescending { it.priority.weight }
                .thenByDescending { it.createdAt }
        )

    Box(modifier = Modifier.fillMaxSize()) {
        Column(modifier = Modifier.fillMaxSize()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(SURFACE)
                    .padding(4.dp)
            ) {
                Horizon.entries.forEach { h ->
                    val selected = horizon == h
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(9.dp))
                            .background(if (selected) SURFACE2 else Color.Transparent)
                            .clickable { horizon = h }
                            .padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = h.name,
                            color = if (selected) Color.White else Color(0xFF64748B),
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }
                }
            }
            Spacer(Modifier.height(14.dp))

            if (visible.isEmpty()) {
                Text("Nothing here yet. Tap + to add a task.", color = MUTED, fontSize = 13.sp)
            }

            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 96.dp)
            ) {
                items(visible, key = { it.id }) { task ->
                    TaskCard(
                        task = task,
                        onDone = {
                            scope.launch {
                                val cal = Calendar.getInstance()
                                dao.updateTask(
                                    task.copy(
                                        status = "DONE",
                                        completedHour = cal.get(Calendar.HOUR_OF_DAY),
                                        dayOfWeekCompleted = cal.get(Calendar.DAY_OF_WEEK),
                                        completedAt = System.currentTimeMillis()
                                    )
                                )
                            }
                        },
                        onDefer = { scope.launch { dao.updateTask(task.copy(deferCount = task.deferCount + 1)) } },
                        onNotDone = { failing = task },
                        onEdit = { editing = task },
                        onUndo = {
                            scope.launch {
                                dao.updateTask(
                                    task.copy(
                                        status = "PENDING",
                                        failReason = null,
                                        completedHour = null,
                                        dayOfWeekCompleted = null,
                                        completedAt = null
                                    )
                                )
                            }
                        }
                    )
                }
            }
        }

        FloatingActionButton(
            onClick = { showAdd = true },
            containerColor = GREEN,
            shape = CircleShape,
            modifier = Modifier.align(Alignment.BottomEnd).padding(bottom = 16.dp)
        ) {
            Icon(Icons.Default.Add, contentDescription = "Add task", tint = Color.Black)
        }
    }

    if (showAdd) {
        TaskDialog(
            initial = null,
            defaultHorizon = horizon,
            onDismiss = { showAdd = false },
            onSave = { title, h, p, c ->
                scope.launch {
                    dao.insertTask(
                        TaskEntity(
                            title = title,
                            horizon = h,
                            priority = p,
                            category = c,
                            monthKey = Keys.month(),
                            periodKey = Keys.forHorizon(h)
                        )
                    )
                    horizon = h
                    showAdd = false
                }
            },
            onDelete = null
        )
    }

    val editTask = editing
    if (editTask != null) {
        TaskDialog(
            initial = editTask,
            defaultHorizon = editTask.horizon,
            onDismiss = { editing = null },
            onSave = { title, h, p, c ->
                scope.launch {
                    dao.updateTask(
                        editTask.copy(
                            title = title,
                            horizon = h,
                            priority = p,
                            category = c,
                            periodKey = if (h != editTask.horizon) Keys.forHorizon(h) else editTask.periodKey
                        )
                    )
                    editing = null
                }
            },
            onDelete = {
                scope.launch {
                    dao.deleteTask(editTask)
                    editing = null
                }
            }
        )
    }

    val failTask = failing
    if (failTask != null) {
        val reasons = listOf("Lack of time", "Too difficult / Blocker", "Low energy", "Procrastinated")
        AlertDialog(
            onDismissRequest = { failing = null },
            containerColor = SURFACE,
            title = { Text("Why wasn't this completed?", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    reasons.forEach { reason ->
                        OutlinedButton(
                            onClick = {
                                scope.launch {
                                    dao.updateTask(failTask.copy(status = "FAILED", failReason = reason))
                                    failing = null
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(reason, color = Color.White, fontSize = 12.sp)
                        }
                    }
                }
            },
            confirmButton = {}
        )
    }
}

@Composable
fun TaskCard(
    task: TaskEntity,
    onDone: () -> Unit,
    onDefer: () -> Unit,
    onNotDone: () -> Unit,
    onEdit: () -> Unit,
    onUndo: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = SURFACE),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = task.priority.label,
                    color = when (task.priority) {
                        Priority.HIGH -> Color(0xFFF87171)
                        Priority.MEDIUM -> Color(0xFFFBBF24)
                        Priority.LOW -> Color(0xFF38BDF8)
                    },
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 10.sp
                )
                Spacer(Modifier.width(8.dp))
                Text(task.category, color = MUTED, fontSize = 10.sp)
                if (task.deferCount > 0) {
                    Spacer(Modifier.width(8.dp))
                    Text("Postponed ${task.deferCount}x", color = AMBER, fontSize = 10.sp)
                }
                Spacer(Modifier.weight(1f))
                IconButton(onClick = onEdit, modifier = Modifier.size(28.dp)) {
                    Icon(Icons.Default.Edit, contentDescription = "Edit", tint = MUTED, modifier = Modifier.size(18.dp))
                }
            }
            Spacer(Modifier.height(6.dp))
            Text(task.title, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
            Spacer(Modifier.height(10.dp))

            if (task.status == "PENDING") {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onDone,
                        contentPadding = PaddingValues(horizontal = 14.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = GREEN)
                    ) { Text("Done", fontSize = 12.sp, color = Color.Black, fontWeight = FontWeight.Bold) }
                    OutlinedButton(onClick = onDefer, contentPadding = PaddingValues(horizontal = 12.dp)) {
                        Text("Later", fontSize = 12.sp)
                    }
                    OutlinedButton(onClick = onNotDone, contentPadding = PaddingValues(horizontal = 12.dp)) {
                        Text("Not done", color = Color(0xFFF87171), fontSize = 12.sp)
                    }
                }
            } else {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = if (task.status == "DONE") "✓ Completed" else "✗ Skipped (${task.failReason ?: "no reason"})",
                        color = if (task.status == "DONE") GREEN else Color(0xFFF87171),
                        fontSize = 12.sp,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = onUndo) { Text("Undo", fontSize = 12.sp) }
                }
            }
        }
    }
}

@Composable
fun TaskDialog(
    initial: TaskEntity?,
    defaultHorizon: Horizon,
    onDismiss: () -> Unit,
    onSave: (String, Horizon, Priority, String) -> Unit,
    onDelete: (() -> Unit)?
) {
    var titleText by remember { mutableStateOf(initial?.title ?: "") }
    var manualHorizon by remember { mutableStateOf<Horizon?>(initial?.horizon) }
    var priority by remember { mutableStateOf(initial?.priority ?: Priority.HIGH) }
    var category by remember { mutableStateOf(initial?.category ?: "Study") }

    val detection = SmartHorizonDetector.classify(titleText, defaultHorizon)
    val finalHorizon = manualHorizon ?: detection.detectedHorizon

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SURFACE,
        title = {
            Text(
                if (initial == null) "New task" else "Edit task",
                color = Color.White, fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                OutlinedTextField(
                    value = titleText,
                    onValueChange = { titleText = it },
                    label = { Text("What do you want to complete?") },
                    modifier = Modifier.fillMaxWidth()
                )
                if (detection.showCautionWarning && manualHorizon == null) {
                    Text(
                        "No time word found (today, this week, this month). Using ${defaultHorizon.name}.",
                        color = Color(0xFFFBBF24), fontSize = 11.sp
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Horizon.entries.forEach { h ->
                        FilterChip(
                            selected = finalHorizon == h,
                            onClick = { manualHorizon = h },
                            label = { Text(h.name, fontSize = 11.sp) }
                        )
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Priority.entries.forEach { p ->
                        FilterChip(
                            selected = priority == p,
                            onClick = { priority = p },
                            label = { Text(p.label, fontSize = 11.sp) }
                        )
                    }
                }
                Row(
                    modifier = Modifier.horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    CATEGORIES.forEach { c ->
                        FilterChip(
                            selected = category == c,
                            onClick = { category = c },
                            label = { Text(c, fontSize = 11.sp) }
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (titleText.isNotBlank()) onSave(titleText.trim(), finalHorizon, priority, category)
                },
                colors = ButtonDefaults.buttonColors(containerColor = GREEN)
            ) {
                Text("Save", color = Color.Black, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            Row {
                if (onDelete != null) {
                    TextButton(onClick = onDelete) { Text("Delete", color = Color(0xFFF87171)) }
                }
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        }
    )
}

// ----- Coach tab -----

@Composable
fun CoachScreen(tasks: List<TaskEntity>, startOnLastMonth: Boolean) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val prefs = remember { SecureStore.prefs(context) }

    var lastMonth by remember { mutableStateOf(startOnLastMonth) }
    val monthKey = if (lastMonth) Keys.prevMonth() else Keys.month()
    val label = Keys.monthLabel(monthKey)
    val periodTasks = tasks.filter { it.monthKey == monthKey }
    val bullets = remember(periodTasks) { LocalCoach.bullets(periodTasks) }

    var aiText by remember(monthKey) { mutableStateOf(prefs.getString("report_$monthKey", null)) }
    var loading by remember { mutableStateOf(false) }
    var error by remember(monthKey) { mutableStateOf<String?>(null) }

    val hasKey = !prefs.getString("gemini_key", "").isNullOrBlank()
    val includeTitles = prefs.getBoolean("include_titles", false)
    val prompt = PromptBuilder.build(periodTasks, label, includeTitles)

    fun askGemini() {
        if (loading) return
        loading = true
        error = null
        val key = prefs.getString("gemini_key", "") ?: ""
        val model = (prefs.getString("gemini_model", DEFAULT_MODEL) ?: DEFAULT_MODEL).ifBlank { DEFAULT_MODEL }
        val mk = monthKey
        val p = prompt
        scope.launch {
            val r = withContext(Dispatchers.IO) { GeminiClient.ask(key, model, p) }
            loading = false
            r.onSuccess { txt ->
                val clean = cleanAi(txt)
                prefs.edit().putString("report_$mk", clean).apply()
                aiText = clean
            }.onFailure { e ->
                error = e.message ?: "Request failed"
            }
        }
    }

    // Opening from the month-end notification: build last month's report automatically if allowed.
    LaunchedEffect(monthKey, periodTasks.size) {
        val auto = prefs.getBoolean("auto_report", true)
        if (lastMonth && auto && hasKey && aiText == null && periodTasks.isNotEmpty()) askGemini()
    }

    LazyColumn(
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(bottom = 24.dp)
    ) {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = !lastMonth, onClick = { lastMonth = false }, label = { Text("This month") })
                FilterChip(selected = lastMonth, onClick = { lastMonth = true }, label = { Text("Last month") })
            }
        }
        item {
            Panel {
                SectionTitle("Quick read: $label")
                Text("Worked out on your phone, nothing sent anywhere.", color = MUTED, fontSize = 11.sp)
                bullets.forEach {
                    Text("• $it", color = Color.White, fontSize = 13.sp)
                }
            }
        }
        item {
            Panel {
                SectionTitle("Gemini coach")
                if (loading) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(10.dp))
                        Text("Reading your month...", color = MUTED, fontSize = 12.sp)
                    }
                }
                val shown = aiText
                if (shown != null) {
                    shown.lines().filter { it.isNotBlank() }.forEach {
                        Text(it, color = Color.White, fontSize = 13.sp)
                    }
                } else if (!loading) {
                    Text(
                        if (hasKey) "Get an AI read of $label with specific things to change."
                        else "Add a free Gemini key in Settings to get an AI report. Or use the share button below with any AI app.",
                        color = MUTED, fontSize = 12.sp
                    )
                }
                val err = error
                if (err != null) Text(err, color = Color(0xFFF87171), fontSize = 12.sp)
                if (hasKey && !loading && periodTasks.isNotEmpty()) {
                    Button(
                        onClick = { askGemini() },
                        colors = ButtonDefaults.buttonColors(containerColor = GREEN)
                    ) {
                        Text(
                            if (shown != null) "Regenerate" else "Ask Gemini",
                            color = Color.Black, fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
        item {
            Panel {
                SectionTitle("Use your own AI")
                Text(
                    "Sends a summary of $label to any AI app you pick, so you can keep asking questions there. Task titles are only included if you turn that on in Settings.",
                    color = MUTED, fontSize = 12.sp
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { shareText(context, prompt) },
                        enabled = periodTasks.isNotEmpty(),
                        colors = ButtonDefaults.buttonColors(containerColor = GREEN)
                    ) { Text("Share to AI app", color = Color.Black, fontWeight = FontWeight.Bold) }
                    OutlinedButton(
                        onClick = { copyText(context, prompt) },
                        enabled = periodTasks.isNotEmpty()
                    ) { Text("Copy") }
                }
            }
        }
    }
}

// ----- Settings tab -----

@Composable
fun SettingsScreen(tasks: List<TaskEntity>) {
    val context = LocalContext.current
    val prefs = remember { SecureStore.prefs(context) }
    var key by remember { mutableStateOf(prefs.getString("gemini_key", "") ?: "") }
    var model by remember { mutableStateOf(prefs.getString("gemini_model", DEFAULT_MODEL) ?: DEFAULT_MODEL) }
    var titles by remember { mutableStateOf(prefs.getBoolean("include_titles", false)) }
    var auto by remember { mutableStateOf(prefs.getBoolean("auto_report", true)) }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Panel {
            SectionTitle("AI coach (optional)")
            Text(
                "Get a free key at aistudio.google.com (Get API key) and paste it here. It is stored encrypted on this phone. Without a key the app never connects to the internet.",
                color = MUTED, fontSize = 12.sp
            )
            OutlinedTextField(
                value = key,
                onValueChange = {
                    key = it
                    prefs.edit().putString("gemini_key", it.trim()).apply()
                },
                label = { Text("Gemini API key") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = model,
                onValueChange = {
                    model = it
                    prefs.edit().putString("gemini_model", it.trim()).apply()
                },
                label = { Text("Model name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Text(
                "If Gemini stops answering, the model name may have been retired. Check the current one in Google AI Studio and paste it here.",
                color = MUTED, fontSize = 11.sp
            )
            SwitchRow(
                "Include task titles",
                "Off: only counts and patterns are sent. On: the AI sees your task names too.",
                titles
            ) {
                titles = it
                prefs.edit().putBoolean("include_titles", it).apply()
            }
            SwitchRow(
                "Auto report at month end",
                "When the month report notification opens the app, it builds the report for you.",
                auto
            ) {
                auto = it
                prefs.edit().putBoolean("auto_report", it).apply()
            }
        }
        Panel {
            SectionTitle("Your data")
            Text(
                "Uninstalling the app or changing phones erases everything, because the database key lives in this phone's secure storage. Export a copy now and then.",
                color = MUTED, fontSize = 12.sp
            )
            Button(
                onClick = { shareText(context, tasksToCsv(tasks)) },
                enabled = tasks.isNotEmpty(),
                colors = ButtonDefaults.buttonColors(containerColor = GREEN)
            ) { Text("Export all tasks (CSV)", color = Color.Black, fontWeight = FontWeight.Bold) }
        }
        Panel {
            SectionTitle("Privacy")
            Text("• Tasks are stored in an AES-256 encrypted database on this phone.", color = GREEN, fontSize = 12.sp)
            Text("• Nothing leaves the phone unless you press Ask Gemini or a share button.", color = GREEN, fontSize = 12.sp)
            Text("• When you do use Gemini, your summary goes to Google. Check Google's terms for the free tier before sending anything private.", color = GREEN, fontSize = 12.sp)
            Text("• If the 8 AM reminder never shows, allow notifications for TaskOrbit in Android settings.", color = MUTED, fontSize = 12.sp)
        }
    }
}
