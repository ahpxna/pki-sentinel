# docs/images/demo.tape — VHS script (https://github.com/charmbracelet/vhs)
# Regenerate the README demo GIF with: vhs docs/images/demo.tape
Output docs/images/demo.gif

Set FontSize 16
Set Width 1200
Set Height 700
Set Theme "Dracula"

Type "cp .env.example .env"
Enter
Sleep 500ms

Type "make bootstrap"
Enter
Sleep 5s

Type "make demo-revoke"
Enter
Sleep 8s

Type "make up-full"
Enter
Sleep 5s

Type "echo 'Grafana: http://localhost:3000  (admin / see .env)'"
Enter
Sleep 2s
