import os
import re
from datetime import datetime
from heapq import merge
from collections import Counter

LOG_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (INFO|WARN|ERROR) (.+)")

# function to parse log lines
def parse_log_lines(line):
  string_match = LOG_PATTERN.match(line)
  if string_match:
    timestamp, level, message = string_match.groups()
    return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S"), level, message
  return None

# Generator to read logs in chunks
def read_logs(file_path):
  with open(file_path, 'r') as file:
    for line in file:
      parsed = parse_log_lines(line)
      if parsed:
        yield parsed

# function to get all log files in directory
def get_log_files(root_dir):
  log_files = []
  for subdir, _, files in os.walk(root_dir):
    for file in files:
      if file.endswith(".log"):
        log_files.append(os.path.join(subdir, file))
  return log_files

# min function to process logs
def process_logs(root_dir):
  log_files = get_log_files(root_dir)
  log_generators = [read_logs(file) for file in log_files]
  merged_logs = merge(*log_generators, key=lambda x: x[0])

  log_level_count = Counter()
  error_messages = Counter()

  # process merged logs
  for timestamp, level, message in merged_logs:
    log_level_count[level] += 1
    if level == "ERROR":
      error_messages[message] += 1

  # Get top 3 most frequent error messages
  top_errors = error_messages.most_common(3)

  # Generate the report
  with open("/content/logs/log_summary.txt", "w") as report:
    report.write("Log Level Summary:\n")
    for level in ["INFO", "WARN", "ERROR"]:
      report.write(f"{level}. {log_level_count[level]}\n")

    report.write("\nTop 3 Error Message:\n")
    for i, (msg, count) in enumerate(top_errors, 1):
      report.write(f"{i}. {msg}: {count}\n ")

  print("log summary generated in log_summary.txt")

if __name__ == "__main__":
  root_directory = "/content/logs"
  process_logs(root_directory)
