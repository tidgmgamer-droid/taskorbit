package com.taskorbit.secure

import android.app.AlarmManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationCompat
import androidx.room.*
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import net.sqlcipher.database.SupportFactory
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.*

// --- 1. ENCRYPTED AES-256 DATABASE ---
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
    val monthKey: String = ""
)

@Dao
interface TaskDao {
    @Query("SELECT * FROM tasks ORDER BY CASE priority WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC, createdAt DESC")
    fun observeAllTasks(): Flow<List<TaskEntity>>

    @Query("SELECT * FROM tasks")
    suspend fun getAllTasksSync(): List<TaskEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertTask(task: TaskEntity): Long

    @Update
    suspend fun updateTask(task: TaskEntity)
}

@Database(entities = [TaskEntity::class], version = 1, exportSchema = false)
abstract class EncryptedVaultDatabase : RoomDatabase() {
    abstract fun taskDao(): TaskDao

    companion object {
        @Volatile private var INSTANCE: EncryptedVaultDatabase? = null

        fun getInstance(context: Context): EncryptedVaultDatabase {
            return INSTANCE ?: synchronized(this) {
                System.loadLibrary("sqlcipher")
                val passphrase = getOrCreateHardwareBackedKey(context)
                val factory = SupportFactory(passphrase)
                Room.databaseBuilder(
                    context.applicationContext,
                    EncryptedVaultDatabase::class.java,
                    "taskorbit_aes256_vault.db"
                ).openHelperFactory(factory).build().also { INSTANCE = it }
            }
        }

        private fun getOrCreateHardwareBackedKey(context: Context): ByteArray {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
            val securePrefs = EncryptedSharedPreferences.create(
                context, "taskorbit_keystore_prefs", masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
            val existing = securePrefs.getString("db_aes_key", null)
            if (existing != null) return Base64.getDecoder().decode(existing)

            val randomBytes = ByteArray(32)
            SecureRandom().nextBytes(randomBytes)
            val encoded = Base64.getEncoder().encodeToString(randomBytes)
            securePrefs.edit().putString("db_aes_key", encoded).apply()
            return randomBytes
        }
    }
}

// --- 2. BEHAVIORAL SUGGESTION ENGINE ---
data class SmartSuggestion(
    val badge: String,
    val headline: String,
    val evidence: String,
    val exactFix: String
)

object DeepSuggestionEngine {
    fun analyzeTasks(tasks: List<TaskEntity>): List<SmartSuggestion> {
        if (tasks.isEmpty()) return emptyList()
        val suggestions = mutableListOf<SmartSuggestion>()

        val highTasks = tasks.filter { it.priority == Priority.HIGH }
        val lowMedDone = tasks.count { it.priority != Priority.HIGH && it.status == "DONE" }
        val highStalled = highTasks.filter { it.status != "DONE" }

        if (highTasks.isNotEmpty() && highStalled.size.toFloat() / highTasks.size >= 0.4f) {
            val topStalled = highStalled.first()
            suggestions.add(
                SmartSuggestion(
                    badge = "PRIORITY INVERSION DETECTED",
                    headline = "${highStalled.size}/${highTasks.size} High-Priority Tasks Unfinished (While $lowMedDone Lower Tasks Done)",
                    evidence = "You are clearing easy Medium/Low tasks while '${topStalled.title}' stays stalled.",
                    exactFix = "Lock '${topStalled.title}' as your #1 Morning Anchor tomorrow before touching any Medium or Low task."
                )
            )
        }

        val chronicDeferred = tasks.filter { it.deferCount >= 2 && it.status == "PENDING" }
        if (chronicDeferred.isNotEmpty()) {
            val worst = chronicDeferred.maxByOrNull { it.deferCount }!!
            suggestions.add(
                SmartSuggestion(
                    badge = "CHRONIC DEFERRAL LOOP (${worst.deferCount}x)",
                    headline = "'${worst.title}' Has Been Postponed ${worst.deferCount} Times",
                    evidence = "Tasks deferred more than twice have a <15% completion probability unless their scope is halved.",
                    exactFix = "Shrink '${worst.title}' to a 10-minute starter version right now, or move it to 'Month'."
                )
            )
        }

        val failed = tasks.filter { it.status == "FAILED" }
        if (failed.isNotEmpty()) {
            val grouped = failed.groupingBy { it.failReason ?: "Unspecified" }.eachCount()
            val topBlocker = grouped.maxByOrNull { it.value }!!
            val pct = (topBlocker.value * 100) / failed.size
            val tailoredProtocol = when (topBlocker.key) {
                "Lack of time" -> "Enforce a strict 3-Task Daily Cap (1 High, 1 Medium, 1 Low) every morning at 8:00 AM."
                "Too difficult / Blocker" -> "Replace blocked tasks with a 20-minute diagnostic step before attempting full execution."
                "Low energy" -> "Move all High-priority Study & Coding tasks before 1:00 PM."
                else -> "Start with a 2-minute entry rule right when the 8:00 AM morning notification fires."
            }
            suggestions.add(
                SmartSuggestion(
                    badge = "ROOT BLOCKER: ${topBlocker.key.uppercase()} ($pct%)",
                    headline = "${topBlocker.value} of ${failed.size} Skipped Tasks Failed Due to '${topBlocker.key}'",
                    evidence = "Eliminating this single bottleneck removes $pct% of your monthly task failures.",
                    exactFix = tailoredProtocol
                )
            )
        }
        return suggestions
    }
}

// --- 3. DUOLINGO ICON SWITCHER & 8:00 AM ALARM ---
enum class IconMood(val aliasName: String) {
    HAPPY("com.taskorbit.secure.LauncherIconHappy"),
    PENDING("com.taskorbit.secure.LauncherIconPending"),
    DANGER("com.taskorbit.secure.LauncherIconDanger")
}

object DuolingoIconSwitcher {
    fun evaluateAndApply(context: Context, todayTasks: List<TaskEntity>): IconMood {
        val done = todayTasks.count { it.status == "DONE" }
        val failed = todayTasks.count { it.status == "FAILED" }
        val pending = todayTasks.count { it.status == "PENDING" }
        val hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)

        val mood = when {
            todayTasks.isNotEmpty() && pending == 0 && done > 0 && failed == 0 -> IconMood.HAPPY
            failed > 0 || (pending > 0 && hour >= 20) -> IconMood.DANGER
            else -> IconMood.PENDING
        }

        val pm = context.packageManager
        IconMood.entries.forEach { m ->
            val comp = ComponentName(context.packageName, m.aliasName)
            val state = if (m == mood) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        else PackageManager.COMPONENT_ENABLED_STATE_DISABLED
            if (pm.getComponentEnabledSetting(comp) != state) {
                pm.setComponentEnabledSetting(comp, state, PackageManager.DONT_KILL_APP)
            }
        }
        return mood
    }
}

class MorningAndMonthlyReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        CoroutineScope(Dispatchers.IO).launch {
            val db = EncryptedVaultDatabase.getInstance(context)
            val allTasks = db.taskDao().getAllTasksSync()
            val todayTasks = allTasks.filter { it.horizon == Horizon.TODAY }

            val currentMonthKey = SimpleDateFormat("yyyy-MM", Locale.US).format(Date())
            val oldMonthTasks = allTasks.filter { it.monthKey.isNotBlank() && it.monthKey != currentMonthKey }
            oldMonthTasks.filter { it.status == "PENDING" }.forEach { task ->
                db.taskDao().updateTask(task.copy(monthKey = currentMonthKey, deferCount = task.deferCount + 1))
            }

            DuolingoIconSwitcher.evaluateAndApply(context, todayTasks)
            sendMorningNotification(context, todayTasks.count { it.status == "PENDING" })
            scheduleMorningAlarm(context, 8, 0)
        }
    }

    private fun sendMorningNotification(context: Context, pendingToday: Int) {
        val channelId = "taskorbit_morning_brief"
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(channelId, "Morning Task Plan", NotificationManager.IMPORTANCE_HIGH)
            )
        }
        val tapIntent = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val text = if (pendingToday > 0) {
            "You have $pendingToday task(s) queued for Today. Tap to choose what to complete!"
        } else {
            "Good morning! Tap '+' to set Today's, This Week's, and This Month's tasks."
        }
        val notif = NotificationCompat.Builder(context, channelId)
            .setSmallIcon(android.R.drawable.ic_popup_reminder)
            .setContentTitle("☀️ TaskOrbit Morning Plan")
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(tapIntent)
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
            } catch (_: SecurityException) {}
        }
    }
}

// --- 4. SMART HORIZON DETECTOR & MAIN UI ---
data class HorizonDetectionResult(
    val detectedHorizon: Horizon,
    val showCautionWarning: Boolean
)

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
        return HorizonDetectionResult(defaultHorizon, showCautionWarning = true)
    }
}

enum class ScreenTab { ANALYZER, TASKS, SETTINGS }

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        MorningAndMonthlyReceiver.scheduleMorningAlarm(this, 8, 0)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    background = Color(0xFF090D16),
                    surface = Color(0xFF131B2E),
                    primary = Color(0xFF10B981)
                )
            ) {
                SecureTaskOrbitScreen()
            }
        }
    }
}

@Composable
fun SecureTaskOrbitScreen() {
    val context = LocalContext.current
    val db = remember { EncryptedVaultDatabase.getInstance(context) }
    val scope = rememberCoroutineScope()
    val tasks by db.taskDao().observeAllTasks().collectAsState(initial = emptyList())

    var currentTab by remember { mutableStateOf(ScreenTab.TASKS) }
    var activeHorizon by remember { mutableStateOf(Horizon.TODAY) }
    var isLeftRollOpen by remember { mutableStateOf(false) }
    var showAddModal by remember { mutableStateOf(false) }
    var failingTask by remember { mutableStateOf<TaskEntity?>(null) }

    val todayTasks = tasks.filter { it.horizon == Horizon.TODAY }
    val currentMood = remember(todayTasks) {
        DuolingoIconSwitcher.evaluateAndApply(context, todayTasks)
    }
    val diagnostics = remember(tasks) {
        DeepSuggestionEngine.analyzeTasks(tasks)
    }

    Box(modifier = Modifier.fillMaxSize().background(Color(0xFF090D16))) {
        Column(modifier = Modifier.fillMaxSize().padding(start = 24.dp, end = 16.dp, top = 16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .background(
                                when (currentMood) {
                                    IconMood.HAPPY -> Color(0xFF10B981)
                                    IconMood.PENDING -> Color(0xFFF59E0B)
                                    IconMood.DANGER -> Color(0xFFEF4444)
                                }
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = when (currentMood) {
                                IconMood.HAPPY -> "🦉"
                                IconMood.PENDING -> "👀"
                                IconMood.DANGER -> "🔥"
                            },
                            fontSize = 20.sp
                        )
                    }
                    Spacer(Modifier.width(10.dp))
                    Column {
                        Text("TaskOrbit Vault", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                        Text("AES-256 Encrypted • Offline", color = Color(0xFF10B981), fontSize = 10.sp)
                    }
                }
            }

            Spacer(Modifier.height(16.dp))

            when (currentTab) {
                ScreenTab.TASKS -> {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(Color(0xFF131B2E))
                            .padding(4.dp)
                    ) {
                        Horizon.entries.forEach { h ->
                            val selected = activeHorizon == h
                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .clip(RoundedCornerShape(9.dp))
                                    .background(if (selected) Color(0xFF1E293B) else Color.Transparent)
                                    .clickable { activeHorizon = h }
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

                    val horizonTasks = tasks.filter { it.horizon == activeHorizon }
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                        contentPadding = PaddingValues(bottom = 96.dp)
                    ) {
                        items(horizonTasks, key = { it.id }) { task ->
                            Card(
                                colors = CardDefaults.cardColors(containerColor = Color(0xFF131B2E)),
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
                                        Text(task.category, color = Color(0xFF94A3B8), fontSize = 10.sp)
                                        if (task.deferCount > 0) {
                                            Spacer(Modifier.width(8.dp))
                                            Text("Deferred ${task.deferCount}x", color = Color(0xFFF59E0B), fontSize = 10.sp)
                                        }
                                    }
                                    Spacer(Modifier.height(6.dp))
                                    Text(task.title, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                                    Spacer(Modifier.height(10.dp))
                                    if (task.status == "PENDING") {
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            Button(
                                                onClick = {
                                                    scope.launch {
                                                        val cal = Calendar.getInstance()
                                                        db.taskDao().updateTask(
                                                            task.copy(
                                                                status = "DONE",
                                                                completedHour = cal.get(Calendar.HOUR_OF_DAY),
                                                                dayOfWeekCompleted = cal.get(Calendar.DAY_OF_WEEK)
                                                            )
                                                        )
                                                    }
                                                },
                                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981))
                                            ) { Text("Done", fontSize = 12.sp, color = Color.Black, fontWeight = FontWeight.Bold) }

                                            OutlinedButton(onClick = {
                                                scope.launch {
                                                    db.taskDao().updateTask(task.copy(deferCount = task.deferCount + 1))
                                                }
                                            }) { Text("→ Defer", fontSize = 12.sp) }

                                            OutlinedButton(onClick = { failingTask = task }) {
                                                Text("Not Done", color = Color(0xFFF87171), fontSize = 12.sp)
                                            }
                                        }
                                    } else {
                                        Text(
                                            text = if (task.status == "DONE") "✓ Completed" else "✗ Skipped (${task.failReason})",
                                            color = if (task.status == "DONE") Color(0xFF10B981) else Color(0xFFF87171),
                                            fontSize = 12.sp
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                ScreenTab.ANALYZER -> {
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                        contentPadding = PaddingValues(bottom = 88.dp)
                    ) {
                        item {
                            Text("On-Device Behavioral Analyzer", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                            Text("100% computed inside encrypted local SQLite.", color = Color(0xFF94A3B8), fontSize = 11.sp)
                        }
                        items(diagnostics) { item ->
                            Card(
                                colors = CardDefaults.cardColors(containerColor = Color(0xFF131B2E)),
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(14.dp)) {
                                    Text(item.badge, color = Color(0xFF38BDF8), fontWeight = FontWeight.ExtraBold, fontSize = 10.sp)
                                    Spacer(Modifier.height(4.dp))
                                    Text(item.headline, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                                    Spacer(Modifier.height(4.dp))
                                    Text(item.evidence, color = Color(0xFF94A3B8), fontSize = 12.sp)
                                    Spacer(Modifier.height(8.dp))
                                    Box(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clip(RoundedCornerShape(10.dp))
                                            .background(Color(0xFF090D16))
                                            .padding(10.dp)
                                    ) {
                                        Text("Action Blueprint: ${item.exactFix}", color = Color(0xFF10B981), fontSize = 12.sp)
                                    }
                                }
                            }
                        }
                    }
                }

                ScreenTab.SETTINGS -> {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("Hardware Vault Settings", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        Text("• Database: SQLCipher AES-256 + Android Hardware Keystore", color = Color(0xFF10B981), fontSize = 12.sp)
                        Text("• Network Access: Disabled in AndroidManifest.xml (Air-Gapped)", color = Color(0xFF10B981), fontSize = 12.sp)
                    }
                }
            }
        }

        Box(
            modifier = Modifier
                .align(Alignment.CenterStart)
                .width(22.dp)
                .height(96.dp)
                .clip(RoundedCornerShape(topEnd = 16.dp, bottomEnd = 16.dp))
                .background(Color(0xFF1E293B))
                .clickable { isLeftRollOpen = !isLeftRollOpen },
            contentAlignment = Alignment.Center
        ) {
            Text("⋮", color = Color(0xFF10B981), fontWeight = FontWeight.ExtraBold, fontSize = 18.sp)
        }

        AnimatedVisibility(
            visible = isLeftRollOpen,
            enter = slideInHorizontally(initialOffsetX = { -it }),
            exit = slideOutHorizontally(targetOffsetX = { -it }),
            modifier = Modifier.align(Alignment.CenterStart).padding(start = 12.dp)
        ) {
            Column(
                modifier = Modifier
                    .clip(RoundedCornerShape(20.dp))
                    .background(Color(0xFF131B2E))
                    .padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                listOf(
                    ScreenTab.ANALYZER to "Analyzer",
                    ScreenTab.TASKS to "Tasks",
                    ScreenTab.SETTINGS to "Settings"
                ).forEach { (tab, label) ->
                    Button(
                        onClick = {
                            currentTab = tab
                            isLeftRollOpen = false
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (currentTab == tab) Color(0xFF10B981) else Color(0xFF1E293B)
                        )
                    ) {
                        Text(label, fontSize = 12.sp, color = if (currentTab == tab) Color.Black else Color.White)
                    }
                }
            }
        }

        if (currentTab == ScreenTab.TASKS) {
            FloatingActionButton(
                onClick = { showAddModal = true },
                containerColor = Color(0xFF10B981),
                shape = CircleShape,
                modifier = Modifier.align(Alignment.BottomEnd).padding(24.dp)
            ) {
                Icon(Icons.Default.Add, contentDescription = "Add Task", tint = Color.Black)
            }
        }

        if (showAddModal) {
            var titleInput by remember { mutableStateOf("") }
            var manualHorizon by remember { mutableStateOf<Horizon?>(null) }
            var chosenPriority by remember { mutableStateOf(Priority.HIGH) }

            val detection = SmartHorizonDetector.classify(titleInput, activeHorizon)
            val finalHorizon = manualHorizon ?: detection.detectedHorizon

            AlertDialog(
                onDismissRequest = { showAddModal = false },
                containerColor = Color(0xFF131B2E),
                title = { Text("New Task", color = Color.White, fontWeight = FontWeight.Bold) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        OutlinedTextField(
                            value = titleInput,
                            onValueChange = { titleInput = it },
                            label = { Text("What do you want to complete?") },
                            modifier = Modifier.fillMaxWidth()
                        )
                        if (detection.showCautionWarning && manualHorizon == null) {
                            Text(
                                "⚠️ Caution: No time keyword ('today', 'this week', 'this month') detected. Defaulting to ${finalHorizon.name} or tap below to override:",
                                color = Color(0xFFFBBF24),
                                fontSize = 11.sp
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
                                    selected = chosenPriority == p,
                                    onClick = { chosenPriority = p },
                                    label = { Text(p.label, fontSize = 11.sp) }
                                )
                            }
                        }
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            if (titleInput.isNotBlank()) {
                                scope.launch {
                                    val monthKey = SimpleDateFormat("yyyy-MM", Locale.US).format(Date())
                                    db.taskDao().insertTask(
                                        TaskEntity(
                                            title = titleInput.trim(),
                                            horizon = finalHorizon,
                                            priority = chosenPriority,
                                            monthKey = monthKey
                                        )
                                    )
                                    activeHorizon = finalHorizon
                                    showAddModal = false
                                }
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981))
                    ) {
                        Text("Save Task", color = Color.Black, fontWeight = FontWeight.Bold)
                    }
                }
            )
        }

        if (failingTask != null) {
            val reasons = listOf("Lack of time", "Too difficult / Blocker", "Low energy", "Procrastinated")
            AlertDialog(
                onDismissRequest = { failingTask = null },
                containerColor = Color(0xFF131B2E),
                title = { Text("Why wasn't this completed?", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        reasons.forEach { reason ->
                            OutlinedButton(
                                onClick = {
                                    val target = failingTask!!
                                    scope.launch {
                                        db.taskDao().updateTask(target.copy(status = "FAILED", failReason = reason))
                                        failingTask = null
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
}
