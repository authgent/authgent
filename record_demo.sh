#!/usr/bin/env bash
# Wrapper: feeds Enter presses with natural delays to demo_showcase.py
# then records with asciinema → converts to GIF with agg

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
CAST="$DIR/docs/assets/demo.cast"
GIF="$DIR/docs/assets/demo.gif"

# Create a named pipe for feeding Enter presses
FIFO=$(mktemp -u /tmp/demo_input.XXXXXX)
mkfifo "$FIFO"

# Feed Enter presses with reading-pace delays (background)
# New demo has 9 enter() calls with typewriter text — needs longer pauses
(
  sleep 22  # Intro: typed problem statement + health check
  echo ""
  sleep 18  # Scene 1: Register three agents (typing + spinners)
  echo ""
  sleep 16  # Scene 2: Orchestrator gets token (typing + claims)
  echo ""
  sleep 20  # Scene 3: Delegate to Search Agent (typing + callouts + panel)
  echo ""
  sleep 18  # Scene 4: Delegate to DB Agent (typing + tree)
  echo ""
  sleep 20  # Scene 5: Scope escalation blocked (typing + table + panel)
  echo ""
  sleep 18  # Scene 6: Token introspection (typing + table)
  echo ""
  sleep 22  # Scene 7: Revocation (typing + before/after table)
  echo ""
  sleep 22  # Scene 8: HITL step-up (typing + polls + audit)
  echo ""
) > "$FIFO" &
FEEDER_PID=$!

# Record with asciinema
asciinema rec \
  --stdin \
  --cols 110 \
  --rows 38 \
  --overwrite \
  --command "python3 $DIR/demo_showcase.py < $FIFO" \
  "$CAST"

wait "$FEEDER_PID" 2>/dev/null || true
rm -f "$FIFO"

echo ""
echo "✓ Recording saved to $CAST"
echo "Converting to GIF..."

# Convert to GIF (1.5x speed, monokai theme)
agg \
  --cols 110 \
  --rows 38 \
  --speed 1.5 \
  --theme monokai \
  --font-size 14 \
  "$CAST" "$GIF"

echo "✓ GIF saved to $GIF"
ls -lh "$GIF"
