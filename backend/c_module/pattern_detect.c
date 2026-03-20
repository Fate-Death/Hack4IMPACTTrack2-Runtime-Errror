/**
 * WebShield AI — C Pattern Detection Module
 * 
 * A lightweight C program that reads input from stdin and checks
 * for SQL Injection and XSS patterns using string matching.
 * Outputs a JSON result to stdout.
 * 
 * Compile: gcc -o pattern_detect pattern_detect.c
 * Usage:   echo "' OR 1=1 --" | ./pattern_detect
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_INPUT 4096
#define MAX_PATTERNS 20

typedef struct {
    const char *pattern;
    const char *type;
    const char *name;
    int weight;
} Pattern;

/* Convert string to lowercase in-place */
void to_lower(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower((unsigned char)str[i]);
    }
}

/* Case-insensitive substring search */
int contains_ci(const char *haystack, const char *needle) {
    char h[MAX_INPUT], n[256];
    strncpy(h, haystack, MAX_INPUT - 1);
    h[MAX_INPUT - 1] = '\0';
    strncpy(n, needle, 255);
    n[255] = '\0';
    to_lower(h);
    to_lower(n);
    return strstr(h, n) != NULL;
}

int main(void) {
    char input[MAX_INPUT];
    int total_read = 0;
    int ch;

    /* Read all input from stdin */
    while ((ch = getchar()) != EOF && total_read < MAX_INPUT - 1) {
        input[total_read++] = (char)ch;
    }
    input[total_read] = '\0';

    /* Remove trailing newline */
    if (total_read > 0 && input[total_read - 1] == '\n') {
        input[total_read - 1] = '\0';
    }

    /* Define patterns to check */
    Pattern patterns[] = {
        {"' or ",       "SQL Injection", "OR-based Injection",       30},
        {"or 1=1",      "SQL Injection", "Tautology Attack",         30},
        {"' or '1'='1", "SQL Injection", "String Tautology",         35},
        {"--",          "SQL Injection", "Comment Injection",        20},
        {"drop table",  "SQL Injection", "DROP TABLE Attack",        40},
        {"union select", "SQL Injection", "UNION SELECT Injection",  35},
        {"delete from", "SQL Injection", "DELETE Attack",            40},
        {"<script",     "XSS",          "Script Tag Injection",      40},
        {"</script>",   "XSS",          "Script Close Tag",          30},
        {"onerror=",    "XSS",          "Event Handler Injection",   35},
        {"onload=",     "XSS",          "Onload Handler",            35},
        {"onclick=",    "XSS",          "Onclick Handler",           35},
        {"javascript:", "XSS",          "JavaScript URI",            35},
        {"<iframe",     "XSS",          "iFrame Injection",          30},
        {"alert(",      "XSS",          "Alert Call",                15},
        {"document.cookie", "XSS",      "Cookie Access",             30},
    };

    int num_patterns = sizeof(patterns) / sizeof(patterns[0]);
    int detected_count = 0;
    int total_weight = 0;
    int detected_indices[MAX_PATTERNS];

    /* Check each pattern */
    for (int i = 0; i < num_patterns; i++) {
        if (contains_ci(input, patterns[i].pattern)) {
            detected_indices[detected_count++] = i;
            total_weight += patterns[i].weight;
            if (detected_count >= MAX_PATTERNS) break;
        }
    }

    /* Cap risk score at 100 */
    int risk_score = total_weight > 100 ? 100 : total_weight;

    /* Determine classification */
    const char *classification;
    if (risk_score == 0) {
        classification = "Safe";
    } else if (risk_score <= 25) {
        classification = "Suspicious";
    } else {
        classification = "Malicious";
    }

    /* Output JSON */
    printf("{\n");
    printf("  \"source\": \"c_module\",\n");
    printf("  \"classification\": \"%s\",\n", classification);
    printf("  \"riskScore\": %d,\n", risk_score);
    printf("  \"patternsDetected\": %d,\n", detected_count);
    printf("  \"patterns\": [");
    for (int i = 0; i < detected_count; i++) {
        int idx = detected_indices[i];
        printf("\n    {\"name\": \"%s\", \"type\": \"%s\", \"weight\": %d}",
               patterns[idx].name, patterns[idx].type, patterns[idx].weight);
        if (i < detected_count - 1) printf(",");
    }
    printf("\n  ]\n");
    printf("}\n");

    return 0;
}
