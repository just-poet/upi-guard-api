Set shell = CreateObject("WScript.Shell")
Set fs = CreateObject("Scripting.FileSystemObject")
folder = fs.GetParentFolderName(WScript.ScriptFullName)
On Error Resume Next
shell.Run "pyw.exe -3 """ & folder & "\companion.py""", 0, False
If Err.Number <> 0 Then
    Err.Clear
    python = shell.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python\Python314\pythonw.exe"
    If fs.FileExists(python) Then
        shell.Run """" & python & """ """ & folder & "\companion.py""", 0, False
    Else
        found = False
        For Each version In Array("315", "314", "313", "312", "311", "310")
            candidate = shell.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python\Python" & version & "\pythonw.exe"
            If fs.FileExists(candidate) Then
                shell.Run """" & candidate & """ """ & folder & "\companion.py""", 0, False
                found = True
                Exit For
            End If
        Next
        If Not found Then MsgBox "UPI Guard needs Python 3 with Tk. Install Python from python.org, then run this launcher again.", 64, "UPI Guard"
    End If
End If
