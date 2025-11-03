import os
import re

# Function to scan a single file for sensitive data patterns
def scan_file(filepath):
    sensitive_patterns = {
        "Email Address": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "Phone Number": r"\b\d{10}\b",
        "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
        "Password": r"(?i)password\s*[:=]\s*[^\s]+",
    }

    results = {}
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            for label, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    results[label] = matches
    except Exception as e:
        print(f"❌ Error reading {filepath}: {e}")
    return results


# Function to scan all files in a folder
def scan_folder(folder):
    all_results = {}
    for root, _, files in os.walk(folder):
        for file in files:
            filepath = os.path.join(root, file)
            findings = scan_file(filepath)
            if findings:
                all_results[filepath] = findings
    return all_results


# Function to save the scan report
def save_report(results, output_file="report.txt"):
    with open(output_file, "w", encoding="utf-8") as f:
        if results:
            for filepath, findings in results.items():
                f.write(f"File: {filepath}\n")
                for label, matches in findings.items():
                    f.write(f"  {label}: {matches}\n")
                f.write("\n")
        else:
            f.write("No sensitive data found.\n")
    print(f"✅ Report saved as {output_file}")


# Main execution
if __name__ == "__main__":
    folder = input("Enter folder path to scan: ").strip()
    if os.path.exists(folder):
        results = scan_folder(folder)
        save_report(results)
    else:
        print("⚠ Folder not found!")