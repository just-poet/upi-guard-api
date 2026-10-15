# UPI Guard Windows floating companion

Run **Start UPI Guard.vbs**. Python 3 with Tk must be installed; no third-party Python packages are required. The launcher uses the installed Python and opens a floating teal shield without a console window.

Right-click the shield → Open checker. In website Settings create a one-time connection code, paste it into the companion and choose Connect code. The connection token is encrypted with Windows DPAPI for your current Windows user. It is separate from the OpenAI key, which stays on the backend. Use a new connection code for each browser/desktop client.

Select text in an ordinary Windows app, then click the shield. The shield preserves focus and asks the source app to copy the selection. Only a fresh copy is submitted. If the app blocks copying, use Paste clipboard in the panel, review it, then choose Check. The companion never scans passively or sends old clipboard data automatically. Public links can be inspected without signing in or running scripts. Risk results cannot prove authenticity.

Drag the shield to move it. Closing the checker panel keeps the shield available. Right-click → Quit exits the application. No automatic startup or global keylogger is installed. The shield stays above normal app windows, but secure/UAC screens and some exclusive full-screen applications cannot be overlaid. Free backend restarts can reset connections/history; reconnect from website Settings if needed.
