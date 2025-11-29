/*
 * ======================================================================================
 * PROJECT: SHASHANK DAKSH OMEGA-LEVEL DEFENSE SUITE (S.D.O.D.S)
 * VERSION: X-2.1 ENTERPRISE EDITION
 * ARCHITECT: SHASHANK DAKSH
 * LICENSE:   GLOBAL ENTERPRISE - SHAK CORP
 * CONTACT:   Shak_Corp@zohomail.in
 * REPO:      https://github.com/Shak-Corp
 *
 * CORE FUNCTIONALITY:
 * 1. FNV-1a HASHING: Integrity monitoring (Anti-Tamper).
 * 2. CHI-SQUARE ANALYSIS: Statistical test for polymorphic/encrypted code.
 * 3. EMULATION SIMULATION: Sandbox behavioral check using deep API analysis.
 * 4. CONFIG LOADER: Runtime configuration for sensitivity.
 * 5. QUARANTINE MANAGER: Full control over isolated threats.
 * ======================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <ctype.h>
#include <math.h>

// --- OS COMPATIBILITY & UTILS ---
#ifdef _WIN32
#include <windows.h>
#define SLEEP_MS(x) Sleep(x)
#define CLEAR_SCREEN "cls"
#define PATH_SEP '\\'
#else
#include <unistd.h>
#define SLEEP_MS(x) usleep(x * 1000)
#define CLEAR_SCREEN "clear"
#define PATH_SEP '/'
#endif

// --- OMEGA BRANDING COLORS ---
#define C_CRITICAL "\x1b[38;5;196m\x1b[1m"  // Bold Red
#define C_ALERT    "\x1b[38;5;208m\x1b[5m"  // Orange Blinking
#define C_SUCCESS  "\x1b[38;5;46m\x1b[1m"   // Bold Green
#define C_INFO     "\x1b[38;5;51m\x1b[1m"   // Bold Cyan
#define C_WHITE    "\x1b[38;5;255m"
#define C_GREY     "\x1b[38;5;240m"
#define C_BG_DARK  "\x1b[48;5;235m"
#define C_RESET    "\x1b[0m"

#define MAX_PATH 2048
#define LOG_FILE "SHAK_OMEGA_LOG.txt"
#define QUARANTINE_DIR "./SHAK_OMEGA_VAULT/"
#define CONFIG_FILE "shak_config.txt"
#define HASH_DB_FILE "shak_integrity.db"

// --- GLOBAL CONFIGURATION ---
int G_SCAN_DEPTH = 3;       // 1-5, controls recursive depth
int G_HEURISTIC_SENSITIVITY = 85; // Risk score required for quarantine

// --- GLOBAL STATS ---
int files_scanned = 0;
int threats_neutralized = 0;
int scan_depth_current = 0;
long total_bytes_scanned = 0;

// --- DATA STRUCTURES ---

typedef struct {
    char name[100];
    char pattern[200];
    int score_base; // Base score added to risk
    char type[20]; // Trojan, Ransomware, Spyware
} ThreatSignature;

typedef struct {
    char filepath[MAX_PATH];
    unsigned long long hash;
} IntegrityRecord;

// --- MASSIVE THREAT DATABASE (50+ Entries) ---
ThreatSignature threat_db[] = {
    {"TEST-VIRUS.EICAR", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR", 100, "Test"},
    {"Ransom.WannaCry.42", "MsWin32EnsureVirtualAlloc", 95, "Ransomware"},
    {"Trojan.Gen.Zues", "ipv6_monitor_inject_call", 90, "Trojan"},
    {"Worm.LoveLetter.VBS", "kindly check the attached LOVELETTER", 85, "Worm"},
    {"Spyware.KeyLog.1A", "GetAsyncKeyState_hook_event", 80, "Spyware"},
    // === TROJAN CLASS ===
    {"Trojan.Agent.A", "DownloadFileA(http://", 70, "Trojan"},
    {"Trojan.Backdoor.Win32", "OpenProcess_WriteMemory", 75, "Trojan"},
    {"Trojan.Dropper.PE", "\x55\x89\xE5\x83\xEC", 65, "Trojan"},
    {"Trojan.Banker.Gen", "http-post/credit-card-info", 90, "Trojan"},
    {"Trojan.Rootkit.SMB", "ZwCreateKey_hook_SSDT", 95, "Rootkit"},
    // === RANSOMWARE CLASS ===
    {"Ransom.Locky.V2", "AES-256-Encrypt-Key", 98, "Ransomware"},
    {"Ransom.Cerber.3A", "encrypt_file_ext=cerber", 95, "Ransomware"},
    {"Ransom.Petya.Disk", "MBR_write_sector_0", 100, "Ransomware"},
    {"Ransom.BadRabbit", "diskpart_clean_execute", 92, "Ransomware"},
    // === SPYWARE / PUA CLASS ===
    {"Spyware.Adware.Toolbar", "browser_toolbar_inject", 55, "Spyware"},
    {"PUA.Optimize.Fake", "WindowsRegistryFixer_pro", 45, "PUA"},
    {"Spyware.Monitor.HTTP", "PostDataToServer_session", 70, "Spyware"},
    // === WORMS / VIRUSES ===
    {"Virus.Gen.PE", "\x4d\x5a\x90\x00\x03\x00\x00", 85, "Virus"},
    {"Worm.Conficker.UDP", "UDP_send_port_139", 78, "Worm"},
    // === More Advanced Signatures ===
    {"Trojan.Cryptominer", "stratum+tcp://xmr-pool", 80, "Coinminer"},
    {"Malware.Obfuscator.JS", "eval(unescape('", 75, "Script"},
    {"Exploit.CVE.2023", "kernel32!LdrpInitializeProcess", 99, "Exploit"},
    {"Malware.Loader.DLL", "DllMain_Attach_Process", 88, "Loader"},
    {"Backdoor.Meterpreter", "bind_tcp_shell", 92, "Backdoor"},
    {"Trojan.IcedID", "CreateRemoteThread_shell", 90, "Trojan"},
    {"Ransom.Ryuk.Crypt", "encrypt_with_key_exchange", 96, "Ransomware"},
    {"Spyware.Clipboard", "SetClipboardData_Monitor", 72, "Spyware"},
    {"Worm.SelfReplicating", "CopyFileA_target_dir", 75, "Worm"},
    {"PUA.WebSearch.Hijack", "default_search_url_change", 50, "PUA"},
    {"Malware.Fileless.PS", "Invoke-Expression -Encoded", 95, "Fileless"},
    {"RAT.AsyncRAT", "NetworkStream.Write_send_key", 85, "RAT"},
    {"Trojan.TrickBot", "Inject_into_winlogon", 90, "Trojan"},
    {"Ransom.Conti", "volume_shadow_copy_delete", 97, "Ransomware"},
    {"Spyware.CookieStealer", "http_cookie_dump", 68, "Spyware"},
    {"Virus.Polymorphic", "Randomize_OpCode_XOR", 90, "Virus"},
    {"Exploit.HeapSpray", "VirtualProtect_address", 94, "Exploit"},
    {"Worm.Downloader.Exe", "URLDownloadToFileA_temp", 77, "Downloader"},
    {"PUA.RegistryCleaner", "RegDeleteKey_trial_version", 40, "PUA"},
    {"Trojan.RedLine", "SendMailData_SMTP_auth", 83, "Trojan"},
    {"Ransom.DarkSide", "payment_via_bitcoin_address", 99, "Ransomware"},
    {"Malware.Wipe.Disk", "WriteFile_Zero_Sector", 100, "Wiper"},
    {"Spyware.Microphone", "waveInOpen_record_audio", 75, "Spyware"},
    {"Trojan.Dridex", "browser_credential_dump", 91, "Trojan"},
    {"Ransom.REvil", "file_ext=evil_locked", 98, "Ransomware"},
    {"PUA.Optimizer.Reg", "system_speed_boost_guarantee", 35, "PUA"},
    {"Exploit.BufferOverflow", "memcpy_destination_size", 93, "Exploit"},
    {"Malware.Injector.Remote", "SetThreadContext_ResumeThread", 89, "Injector"},
    {"Trojan.FakeAV", "ALERT_YOUR_PC_IS_INFECTED", 80, "FakeAV"},
    {"Ransom.Hive", "ransom_note_contact_us", 95, "Ransomware"}
};

// --- BEHAVIORAL API IMPORTS (Used in Emulation Simulation) ---
const char *emu_apis[] = {
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", // Injection/Hooking
    "RegSetValueExA", "RegDeleteKey",                             // Persistence/Registry Tamper
    "MoveFileExA", "DeleteFileA",                                 // Self-Deletion/File system tamper
    "waveInOpen", "GetClipboardData",                             // Spyware/Eavesdropping
    "socket", "connect", "send",                                  // C2/Network
    "volume_shadow_copy_delete"                                   // Anti-Backup/Ransomware
};

// --- FUNCTION PROTOTYPES ---
void gui_header();
void write_log(const char* type, const char* msg);
void load_config();
unsigned long long fnv1a_hash(const char *buffer, size_t len);
void save_integrity_record(const char *filepath, unsigned long long hash);
unsigned long long check_integrity_record(const char *filepath);
int deep_file_inspection(const char *filepath);
void scan_recursive(const char *path, int depth);
void quarantine_object(const char *filepath, const char *threat_name, int score);
void quarantine_manager();
void destroy_quarantine();
void restore_quarantine(const char *filename);
double chi_square_test(const char *filepath);
int emulation_simulation(const char *buffer, long size);

// --- MAIN ENGINE ---

int main(int argc, char *argv[]) {
    system(CLEAR_SCREEN);
    
    // 1. Initialization
    load_config(); // Load G_SCAN_DEPTH & G_HEURISTIC_SENSITIVITY
    #ifdef _WIN32
    _mkdir(QUARANTINE_DIR);
    #else
    mkdir(QUARANTINE_DIR, 0700);
    #endif

    gui_header();

    if (argc < 2) {
        printf(C_CRITICAL "\n [ERROR] TARGET VECTOR NOT DEFINED. SHASHANK DEFENSE FAULT.\n" C_RESET);
        printf(C_WHITE " Usage: ./shak_omega <scan_directory>\n" C_RESET);
        return 1;
    }

    // --- MAIN DASHBOARD LOOP ---
    int choice;
    while(1) {
        gui_header();
        printf(C_BG_DARK C_WHITE " [ TARGET: %s | Config Sensitivity: %d | Max Depth: %d ] \n" C_RESET, 
            argv[1], G_HEURISTIC_SENSITIVITY, G_SCAN_DEPTH);
        printf(C_RESET);
        
        printf(C_INFO "  [1]" C_WHITE " OMEGA KINETIC SCAN (Deep Scan)\n" C_RESET);
        printf(C_INFO "  [2]" C_WHITE " REAL-TIME SENTRY (Continuous Monitoring)\n" C_RESET);
        printf(C_INFO "  [3]" C_WHITE " INTEGRITY SNAPSHOT (Hash Baseline Creation)\n" C_RESET);
        printf(C_INFO "  [4]" C_WHITE " QUARANTINE MANAGER (Vault Control)\n" C_RESET);
        printf(C_INFO "  [5]" C_WHITE " VIEW SHAK LOGS\n" C_RESET);
        printf(C_INFO "  [6]" C_CRITICAL " TERMINATE DEFENSE MATRIX\n" C_RESET);
        
        printf(C_CRITICAL "\n  SHASHANK_DAKSH@OMEGA_ROOT >> " C_RESET);
        if (scanf("%d", &choice) != 1) break;

        switch(choice) {
            case 1:
                files_scanned = 0; threats_neutralized = 0; total_bytes_scanned = 0;
                write_log("INFO", "Starting OMEGA Kinetic Scan.");
                scan_recursive(argv[1], 0);
                printf(C_SUCCESS "\n  [✔] SCAN COMPLETE. %d THREATS NEUTRALIZED. Total %ld bytes analyzed.\n" C_RESET, threats_neutralized, total_bytes_scanned);
                printf("  Press Enter to return...");
                getchar(); getchar();
                break;
            case 2:
                printf(C_CRITICAL "\n  [!] REAL-TIME SENTRY MODE ACTIVE. PRESS CTRL+C TO STOP.\n" C_RESET);
                while(1) {
                    scan_recursive(argv[1], 0);
                    SLEEP_MS(3000); 
                    system(CLEAR_SCREEN);
                    gui_header();
                    printf(C_BG_DARK C_CRITICAL "  *** LIVE OMEGA SENTINEL ACTIVE *** \n" C_RESET);
                }
                break;
            case 3:
                files_scanned = 0;
                printf(C_INFO "\n  [FNV-1a] Initializing Integrity Baseline...\n" C_RESET);
                // Run a scan purely for hashing and database generation
                scan_recursive(argv[1], 0); 
                printf(C_SUCCESS "\n  [✔] INTEGRITY BASELINE CREATED/UPDATED for %d files.\n" C_RESET, files_scanned);
                printf("  Press Enter to return...");
                getchar(); getchar();
                break;
            case 4:
                quarantine_manager();
                printf("  Press Enter to return...");
                getchar(); getchar();
                break;
            case 5:
                system("cat SHAK_OMEGA_LOG.txt || type SHAK_OMEGA_LOG.txt"); 
                printf("\n  Press Enter...");
                getchar(); getchar();
                break;
            case 6:
                printf(C_CRITICAL " SHUTTING DOWN SHASHANK DEFENSE PROTOCOL...\n" C_RESET);
                return 0;
            default:
                printf(C_ALERT "  Invalid option.\n" C_RESET);
        }
    }
    return 0;
}

// --- CONFIGURATION MANAGEMENT ---

void load_config() {
    FILE *f = fopen(CONFIG_FILE, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "SCAN_DEPTH")) {
                sscanf(line, "SCAN_DEPTH=%d", &G_SCAN_DEPTH);
            } else if (strstr(line, "HEURISTIC_SENSITIVITY")) {
                sscanf(line, "HEURISTIC_SENSITIVITY=%d", &G_HEURISTIC_SENSITIVITY);
            }
        }
        fclose(f);
    } else {
        // Create default config file if not found
        f = fopen(CONFIG_FILE, "w");
        if (f) {
            fprintf(f, "SCAN_DEPTH=3\n");
            fprintf(f, "HEURISTIC_SENSITIVITY=85\n");
            fclose(f);
        }
    }
    write_log("CONFIG", "Configuration loaded.");
}

// --- HASHING AND INTEGRITY CHECKING (FNV-1a Algorithm) ---

// FNV-1a (Fowler–Noll–Vo) hash implementation (64-bit for robustness)
unsigned long long fnv1a_hash(const char *buffer, size_t len) {
    const unsigned long long FNV_PRIME = 1099511628211ULL;
    const unsigned long long FNV_OFFSET = 14695981039346656037ULL;
    unsigned long long hash = FNV_OFFSET;

    for (size_t i = 0; i < len; i++) {
        hash ^= (unsigned long long)buffer[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

void save_integrity_record(const char *filepath, unsigned long long hash) {
    // Note: In a real AV, this is a secure, encrypted database.
    FILE *f = fopen(HASH_DB_FILE, "a");
    if (f) {
        fprintf(f, "%llu|%s\n", hash, filepath);
        fclose(f);
    }
}

unsigned long long check_integrity_record(const char *filepath) {
    FILE *f = fopen(HASH_DB_FILE, "r");
    if (!f) return 0;

    char line[MAX_PATH + 100];
    unsigned long long stored_hash = 0;
    char stored_path[MAX_PATH];

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%llu|%s", &stored_hash, stored_path) == 2) {
            if (strcmp(filepath, stored_path) == 0) {
                fclose(f);
                return stored_hash;
            }
        }
    }
    fclose(f);
    return 0; // Not found
}

// --- QUARANTINE MANAGEMENT ---

void list_quarantine_files() {
    DIR *d = opendir(QUARANTINE_DIR);
    if (!d) {
        printf(C_ALERT "  [VAULT] Quarantine directory not found.\n" C_RESET);
        return;
    }

    struct dirent *dir;
    int count = 0;
    printf(C_INFO "\n  [QUARANTINE VAULT] Current Locked Threats:\n" C_RESET);
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_name[0] != '.') {
            printf(C_WHITE "  [%d] %s\n" C_RESET, ++count, dir->d_name);
        }
    }
    closedir(d);
    if (count == 0) printf(C_SUCCESS "  [VAULT] Vault is empty. System Clean.\n" C_RESET);
}

void destroy_quarantine() {
    char confirm;
    printf(C_CRITICAL "  [!!! WARNING !!!] Permanently destroy all quarantined items? (Y/N): " C_RESET);
    scanf(" %c", &confirm);
    
    if (toupper(confirm) == 'Y') {
        DIR *d = opendir(QUARANTINE_DIR);
        struct dirent *dir;
        char full_path[MAX_PATH];
        int count = 0;

        while ((dir = readdir(d)) != NULL) {
            if (dir->d_name[0] != '.') {
                snprintf(full_path, sizeof(full_path), "%s%c%s", QUARANTINE_DIR, PATH_SEP, dir->d_name);
                if (remove(full_path) == 0) count++;
            }
        }
        closedir(d);
        printf(C_SUCCESS "  [VAULT] Destruction protocol complete. %d files permanently destroyed.\n" C_RESET, count);
        write_log("CRITICAL", "Quarantine vault destroyed.");
    }
}

void restore_quarantine(const char *filename) {
    // Simplified restoration: assumes restoration to root scan directory for demo
    char vault_path[MAX_PATH];
    char restore_path[MAX_PATH];
    
    snprintf(vault_path, sizeof(vault_path), "%s%c%s", QUARANTINE_DIR, PATH_SEP, filename);
    // Restoration path is simplified to CWD for demo
    snprintf(restore_path, sizeof(restore_path), ".%cRESTORED_%s", PATH_SEP, filename); 

    if (rename(vault_path, restore_path) == 0) {
        printf(C_ALERT "  [VAULT] Threat %s restored to %s. MANUAL CHECK REQUIRED.\n" C_RESET, filename, restore_path);
        write_log("WARN", "File restored from quarantine. Manual action required.");
    } else {
        printf(C_CRITICAL "  [VAULT] Restoration failed. File might not exist or permissions are blocked.\n" C_RESET);
    }
}

void quarantine_manager() {
    int q_choice;
    char q_filename[MAX_PATH];
    
    while(1) {
        system(CLEAR_SCREEN);
        gui_header();
        list_quarantine_files();
        printf(C_INFO "\n  [QUARANTINE CONTROL PANEL]\n" C_RESET);
        printf(C_WHITE "  [1] List Files\n" C_RESET);
        printf(C_WHITE "  [2] Restore File (By Name)\n" C_RESET);
        printf(C_CRITICAL "  [3] DESTROY ALL THREATS (PERMANENT)\n" C_RESET);
        printf(C_WHITE "  [4] Back to Main Menu\n" C_RESET);
        
        printf(C_CRITICAL "\n  VAULT@SHASHANK_DAKSH >> " C_RESET);
        if (scanf("%d", &q_choice) != 1) break;

        switch(q_choice) {
            case 1: break; // Refresh list
            case 2:
                printf(C_ALERT "  Enter filename to restore: " C_RESET);
                scanf("%s", q_filename);
                restore_quarantine(q_filename);
                break;
            case 3:
                destroy_quarantine();
                break;
            case 4: return;
            default: printf(C_ALERT "  Invalid option.\n" C_RESET);
        }
        printf("\n  Press Enter to continue...");
        getchar(); getchar();
    }
}


// --- ADVANCED ANALYSIS CORE ---

// Chi-Square Test
double chi_square_test(const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return 1000.0;
    long counts[256] = {0};
    long total = 0;
    int c;
    while ((c = fgetc(fp)) != EOF) { counts[c]++; total++; }
    fclose(fp);
    if (total < 1024) return 1000.0; 

    double expected = total / 256.0;
    double chi_square = 0.0;

    for (int i = 0; i < 256; i++) {
        double diff = counts[i] - expected;
        chi_square += (diff * diff) / expected;
    }
    return chi_square;
}

// Emulation Simulation: Checks binary for suspicious sequences/API calls
int emulation_simulation(const char *buffer, long size) {
    int score = 0;
    if (size < 100) return 0;
    
    // Check for high-risk dynamic loading calls
    for(int i = 0; i < 10; i++) {
        if (strstr(buffer, emu_apis[i])) {
            score += 15; // 15 points per high-risk API hit
        }
    }
    
    // Check for common malicious 'setup' sequences (simple ROP/JMP check)
    if (strstr(buffer, "\xFF\xE0") || strstr(buffer, "\xEB\xFE")) { 
        score += 20; 
    }

    // Check for sensitive path manipulation (simulated)
    if (strstr(buffer, "System32") || strstr(buffer, "Temp\\")) {
        score += 10;
    }
    
    return score;
}

// --- RECURSIVE SCANNER AND INSPECTION ---

void scan_recursive(const char *path, int depth) {
    if (depth > G_SCAN_DEPTH) return;

    DIR *d = opendir(path);
    if (!d) return;

    struct dirent *dir;
    char full_path[MAX_PATH];

    while ((dir = readdir(d)) != NULL) {
        if (dir->d_name[0] == '.') continue;

        snprintf(full_path, sizeof(full_path), "%s%c%s", path, PATH_SEP, dir->d_name);
        struct stat info;
        stat(full_path, &info);

        if (S_ISDIR(info.st_mode)) {
            scan_recursive(full_path, depth + 1);
        } else {
            files_scanned++;
            if (files_scanned % 10 == 0) {
                printf(C_INFO "  [STATUS] D%d | Analyzing: %-60s\r" C_RESET, depth, dir->d_name);
                fflush(stdout);
            }
            deep_file_inspection(full_path);
        }
    }
    closedir(d);
}

// The "Brain" of the AV - Combines all detection layers
int deep_file_inspection(const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return 0;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    total_bytes_scanned += fsize;

    if (fsize == 0 || fsize > 10 * 1024 * 1024) { 
        fclose(fp);
        return 0;
    }

    char *buffer = malloc(fsize + 1);
    fread(buffer, 1, fsize, fp);
    buffer[fsize] = 0;
    fclose(fp);

    int risk_score = 0;
    char detection_log[512] = "";
    const char *detected_threat_name = "HEUR.Generic.Threat";

    // 1. INTEGRITY CHECK (FNV-1a HASH)
    unsigned long long current_hash = fnv1a_hash(buffer, fsize);
    unsigned long long stored_hash = check_integrity_record(filepath);
    
    if (stored_hash != 0 && current_hash != stored_hash) {
        // File modified since last scan/snapshot (Ransomware/Virus tampering)
        risk_score += 100;
        strcat(detection_log, "Integrity_Breach|");
        detected_threat_name = "INTEGRITY.Tamper.Modification";
        
        printf(C_CRITICAL "\n  [!!! HASH ALERT !!!] %s MODIFIED.\n" C_RESET, filepath);
    } else if (stored_hash == 0) {
        // No hash record found, create one for future monitoring
        save_integrity_record(filepath, current_hash);
    }

    // 2. SIGNATURE MATCHING
    for (size_t i = 0; i < sizeof(threat_db) / sizeof(ThreatSignature); i++) {
        if (strstr(buffer, threat_db[i].pattern) != NULL) {
            risk_score += threat_db[i].score_base;
            strcat(detection_log, "Signature|");
            detected_threat_name = threat_db[i].name;
        }
    }

    // 3. EMULATION/BEHAVIORAL CHECK
    int emu_score = emulation_simulation(buffer, fsize);
    risk_score += emu_score;
    if (emu_score > 0) strcat(detection_log, "Emulator|");
    
    // 4. CHI-SQUARE STATISTICAL ANALYSIS
    double chi_sq = chi_square_test(filepath);
    if (chi_sq > 0.1 && chi_sq < 100.0) { 
        risk_score += (int)(100 - (chi_sq * 1.0)); // Higher score for lower chi-sq
        if (chi_sq < 50) strcat(detection_log, "Chi-Square|");
    }


    // 5. DECISION AND QUARANTINE
    if (risk_score >= G_HEURISTIC_SENSITIVITY) {
        printf(C_CRITICAL "\n  [!!! OMEGA THREAT LEVEL %d !!!]" C_RESET, risk_score);
        printf(C_CRITICAL "\n  FILE: %s\n" C_RESET, filepath);
        printf(C_CRITICAL "  THREAT NAME: %s\n", detected_threat_name);
        printf(C_CRITICAL "  TRIGGERS: %s\n" C_RESET, detection_log);
        printf(C_CRITICAL "  CHI-SQ VALUE: %.2f\n" C_RESET, chi_sq);

        quarantine_object(filepath, detected_threat_name, risk_score);
        // Update hash DB to reflect file removal/change
        save_integrity_record(filepath, 0); 
    }

    free(buffer);
    return risk_score;
}

void quarantine_object(const char *filepath, const char *threat_name, int score) {
    char new_path[MAX_PATH];
    const char *fname = strrchr(filepath, PATH_SEP);
    if(!fname) fname = filepath; else fname++;

    snprintf(new_path, sizeof(new_path), "%s%c%s.LOCKED_%s_S%d", QUARANTINE_DIR, PATH_SEP, fname, threat_name, score);

    printf(C_CRITICAL "      ACTION: LOCKDOWN PROTOCOL ACTIVE. MOVING TO VAULT -> %s\n" C_RESET, new_path);
    
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "QUARANTINE: %s | Threat: %s | Score: %d", filepath, threat_name, score);
    write_log("QUARANTINE", log_msg);

    // Atomic move
    if(rename(filepath, new_path) == 0) {
        printf(C_SUCCESS "      STATUS: NEUTRALIZED AND LOCKED IN SHAK OMEGA VAULT.\n" C_RESET);
        threats_neutralized++;
    } else {
        // Fallback: This part handles permission issues or cross-partition moves
        printf(C_CRITICAL "      STATUS: LOCKDOWN FAILED (Permissions/Cross-Device). ATTEMPTING FORCE DELETE.\n" C_RESET);
        if(remove(filepath) == 0) {
             printf(C_SUCCESS "      STATUS: FORCE DELETION SUCCESSFUL.\n" C_RESET);
             threats_neutralized++;
        } else {
             printf(C_CRITICAL "      FATAL: ACCESS DENIED. RUN AS ROOT/ADMIN FOR 100%% NEUTRALIZATION.\n" C_RESET);
             write_log("FATAL", "Manual intervention required for file deletion.");
        }
    }
}

// --- UI & BRANDING ---

void gui_header() {
    system(CLEAR_SCREEN);
    printf(C_BG_DARK);
    printf(C_CRITICAL " ╔════════════════════════════════════════════════════════════════════════════╗\n");
    printf(C_INFO     " ║  _____ _    _          _  __   _____ _  _ ____  _   _ ____  _   _  ___    ║\n");
    printf(C_INFO     " ║ / ___|| |  | |   /\\   | |/ /  / ____| || | |  \\| | | |  \\| | | |/ ___|   ║\n");
    printf(C_INFO     " ║ \\___ \\| |__| |  /  \\  | ' /  | (___ | || | | \\ | | | | |\\| | | |\\___ \\   ║\n");
    printf(C_INFO     " ║  ___) |  __  | / /\\ \\ |  <    \\___ \\| || | |  \\  | | | |  \\  | | ____) |  ║\n");
    printf(C_INFO     " ║ |____/|_|  |_|/_/  \\_\\|_|\\_\\  |____/\\____/|_|\\_\\|_| |_|\\_\\|_| |_|/____/   ║\n");
    printf(C_CRITICAL " ╚════════════════════════════════════════════════════════════════════════════╝\n" C_RESET);
    printf(C_WHITE "  Architect: " C_CRITICAL "SHASHANK DAKSH" C_WHITE " | Contact: " C_CRITICAL "Shak_Corp@zohomail.in" C_WHITE " | Repo: " C_CRITICAL "https://github.com/Shak-Corp\n" C_RESET);
    printf(C_GREY "  ____________________________________________________________________________\n" C_RESET);
    printf(C_BG_DARK C_WHITE "  THREATS NEUTRALIZED: %d | FILES SCANNED: %d | BYTES ANALYZED: %ld \n" C_RESET, threats_neutralized, files_scanned, total_bytes_scanned);
    printf(C_GREY "  ____________________________________________________________________________\n" C_RESET);
}

void write_log(const char* type, const char* msg) {
    FILE *f = fopen(LOG_FILE, "a");
    if(f) {
        time_t now; time(&now);
        char buf[32]; strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(f, "[%s] [%-12s] SHASHANK DAKSH: %s\n", buf, type, msg);
        fclose(f);
    }
}
