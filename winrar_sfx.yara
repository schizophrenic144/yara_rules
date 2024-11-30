rule WINRAR_SFX
{
    meta:
        author = "schizophrenic144"
        description = "Detects Winrar SFXs"
        date = "2024-11-30"

    strings:
	$magic1 = "Rar!"
	$msgs1 = "You need to have the following volume to continue extraction:" wide
	$msgs2 = "WinRAR self-extracting archive" wide
	$msgs3 = "WinRAR SFX"
	$msgs4 = "Main archive header is corrupt" wide
    condition:
        all of them
        
}
