-- App Info
-- Shows the version, minimum macOS and architecture of a Mac app,
-- plus the last macOS it can run on (same rules as Arca).
-- Run it to pick an app, or export it as an application and drop apps on it.

on run
	repeat
		try
			set theApp to choose file with prompt "Choose an app to inspect:" of type {"com.apple.application-bundle"} default location (path to applications folder)
		on error
			return -- Cancel
		end try
		if not showReport(theApp) then exit repeat
	end repeat
end run

on open droppedItems
	repeat with anItem in droppedItems
		if not showReport(anItem) then exit repeat
	end repeat
end open

-- Shows the dialog. Returns true when the user wants to check another app.
on showReport(theApp)
	set report to inspectApp(theApp)
	set answer to button returned of (display dialog report with title "App Info" buttons {"Copy", "Check another", "Done"} default button "Check another")
	if answer is "Copy" then
		set the clipboard to report
		display notification "Copied to the clipboard" with title "App Info"
		return false
	end if
	return (answer is "Check another")
end showReport

on inspectApp(theApp)
	set appPath to POSIX path of theApp
	if appPath ends with "/" then set appPath to text 1 thru -2 of appPath
	set plist to appPath & "/Contents/Info.plist"

	-- Name and version
	set appName to readKey(plist, "CFBundleDisplayName")
	if appName is "" then set appName to readKey(plist, "CFBundleName")
	if appName is "" then set appName to do shell script "basename " & quoted form of appPath & " .app"
	set appVersion to readKey(plist, "CFBundleShortVersionString")
	set appBuild to readKey(plist, "CFBundleVersion")
	if appVersion is "" then set appVersion to appBuild
	if appVersion is "" then set appVersion to "not listed"
	if appBuild is not "" and appBuild is not appVersion then set appVersion to appVersion & "  (build " & appBuild & ")"
	set bundleID to readKey(plist, "CFBundleIdentifier")

	-- Minimum macOS
	set minOS to readKey(plist, "LSMinimumSystemVersion")
	if minOS is "" then
		set perArch to readKey(plist, "LSMinimumSystemVersionByArchitecture")
		if perArch is not "" then
			set minOS to "per architecture: " & perArch
		else
			set minOS to "not listed in the app (check the developer's release notes)"
		end if
	end if

	-- Architecture, read from the app's executable
	set exeName to readKey(plist, "CFBundleExecutable")
	set fileInfo to ""
	if exeName is not "" then
		try
			set fileInfo to do shell script "file -b " & quoted form of (appPath & "/Contents/MacOS/" & exeName)
		end try
	end if
	set hasArm to (fileInfo contains "arm64")
	set hasX64 to (fileInfo contains "x86_64")
	set hasI386 to (fileInfo contains "i386")
	set hasPPC to (fileInfo contains "ppc")

	if hasArm and hasX64 then
		set arch to "Universal"
		set lastOS to "not known yet"
	else if hasArm then
		set arch to "Apple Silicon"
		set lastOS to "not known yet (needs macOS 11 or later)"
	else if hasX64 then
		set arch to "Intel 64-bit"
		set lastOS to "27 via Rosetta 2 on Apple Silicon (26 on Intel Macs)"
	else if hasI386 then
		set arch to "Intel 32-bit"
		if hasPPC then set arch to "Intel 32-bit (old Universal: PowerPC + Intel)"
		set lastOS to "10.14.6 Mojave"
	else if hasPPC then
		set arch to "PowerPC"
		set lastOS to "10.6.8 Snow Leopard (via Rosetta 1)"
	else
		set arch to "unknown"
		set lastOS to "unknown"
	end if

	set archDetail to ""
	set found to {}
	if hasArm then set end of found to "arm64"
	if hasX64 then set end of found to "x86_64"
	if hasI386 then set end of found to "i386"
	if hasPPC then set end of found to "ppc"
	if found is not {} then
		set AppleScript's text item delimiters to ", "
		set archDetail to "  (" & (found as text) & ")"
		set AppleScript's text item delimiters to ""
	end if

	set report to appName & return & return
	set report to report & "Version:  " & appVersion & return
	set report to report & "Minimum macOS:  " & minOS & return
	set report to report & "Architecture:  " & arch & archDetail & return
	set report to report & "Last macOS:  " & lastOS & return
	if bundleID is not "" then set report to report & "Bundle ID:  " & bundleID & return
	return report
end inspectApp

-- Reads one key from Info.plist (works for text and binary plists). Returns "" when missing.
on readKey(plist, keyName)
	try
		return do shell script "/usr/libexec/PlistBuddy -c " & quoted form of ("Print :" & keyName) & " " & quoted form of plist
	on error
		return ""
	end try
end readKey
