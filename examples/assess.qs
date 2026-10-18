# assess.qs — a runnable example of the shared QYVORA scripting engine driving
# amina's local host assessment.

# Use simulate mode so this runs anywhere without touching the actual host.
set assess.simulate -> "true"
set assess.fixture -> "builtin"

# Run the full assessment.
run assess

# Read live properties from the completed assessment via $(...).
echo -> "framework  = $(result.framework)"
echo -> "findings   = $(result.findings)"
echo -> "modules    = $(result.modules)"
echo -> "risk_score = $(result.risk_score)"
echo -> "risk_level = $(result.risk_level)"

# Show metadata and write a JSON report.
show assess
report -> "amina-report.json"

echo -> "done"
