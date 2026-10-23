#!/bin/sh
# TEST FIXTURE - synthetic PHP binary stub for the tool smoke run; do not deploy.
case "$1" in
  -v) echo "PHP 8.4.26 (cli) (built: Oct  2 2026 00:00:00) (NTS)";;
  -i) echo "session.upload_progress.enabled => 1 => 1"
      echo "session.upload_progress.cleanup => 1 => 1"
      echo "memory_limit => 16M => 16M"
      echo "post_max_size => 8M => 8M"
      echo "upload_max_filesize => 2M => 2M"
      echo "max_file_uploads => 20 => 20";;
  *) : ;;
esac
