#include "stdafx.h"
#include "verinfo.h"

char * GetFileNameFromHandle( HANDLE hFile );

HMODULE gamedll;
DWORD gamedllsize;

int gameversion = 23;

bool oldversion = false;

typedef DWORD( __stdcall * pGetFileSize ) ( HANDLE file , LPDWORD lpFileSizeHigh );
pGetFileSize orgGetFileSize;
pGetFileSize ptrGetFileSize;

DWORD  __stdcall myGetFileSize( HANDLE file , LPDWORD lpFileSizeHigh )
{
	DWORD retval = ptrGetFileSize( file , lpFileSizeHigh );

	if ( retval > 0 )
	{
		char * filenamex = GetFileNameFromHandle( file );

		if ( !filenamex || !strstr( filenamex , ".w3x" ) /*&& !strstr( filenamex , ".w3m" )*/ )
		{
			delete[ ] filenamex;
			return retval;
		}
		delete[ ] filenamex;

		if ( !oldversion )
		{
			if ( retval > 0x7FFFFF )
			{
				retval = 0x7FFFFF;
			}
		}
		else
		{
			if ( retval > 0x2FFFFF )
			{
				retval = 0x2FFFFF;
			}
		}
	}

	return retval;
}



char * GetFileNameFromHandle( HANDLE hFile )
{
	TCHAR * pszFilename = new TCHAR[ MAX_PATH + 1 ];
	HANDLE hFileMap;
	// Create a file mapping object.
	hFileMap = CreateFileMapping( hFile ,
								  NULL ,
								  PAGE_READONLY ,
								  0 ,
								  1 ,
								  NULL );

	if ( hFileMap )
	{
		// Create a file mapping to get the file name.
		void* pMem = MapViewOfFile( hFileMap , FILE_MAP_READ , 0 , 0 , 1 );

		if ( pMem )
		{
			if ( GetMappedFileName( GetCurrentProcess( ) ,
				pMem ,
				pszFilename ,
				MAX_PATH ) )
			{

				// Translate path with device name to drive letters.
				TCHAR szTemp[ BUFSIZE ];
				szTemp[ 0 ] = '\0';

				if ( GetLogicalDriveStrings( BUFSIZE - 1 , szTemp ) )
				{
					TCHAR szName[ MAX_PATH ];
					TCHAR szDrive[ 3 ] = TEXT( " :" );
					BOOL bFound = FALSE;
					TCHAR* p = szTemp;

					do
					{
						// Copy the drive letter to the template string
						*szDrive = *p;

						// Look up each device name
						if ( QueryDosDevice( szDrive , szName , MAX_PATH ) )
						{
							size_t uNameLen = _tcslen( szName );

							if ( uNameLen < MAX_PATH )
							{
								bFound = _tcsnicmp( pszFilename , szName , uNameLen ) == 0
									&& *( pszFilename + uNameLen ) == _T( '\\' );

								if ( bFound )
								{
									// Reconstruct pszFilename using szTempFile
									// Replace device path with DOS path
									TCHAR szTempFile[ MAX_PATH ];
									StringCchPrintf( szTempFile ,
													 MAX_PATH ,
													 TEXT( "%s%s" ) ,
													 szDrive ,
													 pszFilename + uNameLen );
									StringCchCopyN( pszFilename , MAX_PATH + 1 , szTempFile , _tcslen( szTempFile ) );
								}
							}
						}

						// Go to the next NULL character.
						while ( *p++ );
					}
					while ( !bFound && *p ); // end of string
				}
			}
			UnmapViewOfFile( pMem );
		}

		CloseHandle( hFileMap );
	}
	return pszFilename;
}


struct backupmem
{
	DWORD dest;
	BYTE backmem[ 256 ];
	BYTE newmem[ 256 ];
};

vector<backupmem> avoidahdetect;

bool IsGame( void ) // my offset + public
{
	if ( oldversion )
		return false;
	if ( gameversion == 24 )
		return *( int* ) ( ( DWORD ) gamedll + 0xAE64D8 ) > 0;
	return *( int* ) ( ( DWORD ) gamedll + 0xACF678 ) > 0 || *( int* ) ( ( DWORD ) gamedll + 0xAB62A4 ) > 0;
}

bool ingame = false;

// avoid antihack detection
DWORD __stdcall DisableIngameHookThread( LPVOID )
{
	while ( true )
	{
		if ( IsGame( ) )
		{
			if ( !ingame )
			{
				ingame = true;
				MH_DisableHook( orgGetFileSize );
			}
		}
		else
		{
			if ( ingame )
			{
				MH_EnableHook( orgGetFileSize );
			}

		}
		Sleep( 100 );
	}

	return 0;
}



DWORD __stdcall DisableIngameHookThreadMethod2Detected( LPVOID )
{
	DWORD gamedlladdr = ( DWORD ) gamedll;
	unsigned char buffer[ 256 ];
	unsigned char backup[ 256 ];
	DWORD oldprot;


	for ( unsigned int i = 0; i < gamedllsize - 256; i++ )
	{

		// Copy 256 bytes to buffer and copy
		VirtualProtect( ( LPVOID ) ( gamedlladdr + i ) , 256 , PAGE_EXECUTE_READWRITE , &oldprot );
		CopyMemory( buffer , ( LPVOID ) ( gamedlladdr + i ) , 256 );
		CopyMemory( backup , buffer , 256 );
		VirtualProtect( ( LPVOID ) ( gamedlladdr + i ) , 256 , oldprot , 0 );

		bool needrewrite = false;
		int n;

		// Search size limit and replace
		for ( n = 0; n < 251; n++ )
		{
			if ( !oldversion )
			{
				if ( buffer[ n ] == 0x3D && buffer[ n + 1 ] == 0x00 && buffer[ n + 2 ] == 0x00 && buffer[ n + 3 ] == 0x80 && buffer[ n + 4 ] == 0x00 )
				{
					buffer[ n + 3 ] = 0x00;
					buffer[ n + 4 ] = 0x80;
					Beep( 450 , 200 );
					needrewrite = true;
					break;
				}
			}
			else
			{
				if ( buffer[ n ] == 0x3D && buffer[ n + 1 ] == 0x00 && buffer[ n + 2 ] == 0x00 && buffer[ n + 3 ] == 0x40 && buffer[ n + 4 ] == 0x00 )
				{
					buffer[ n + 3 ] = 0x00;
					buffer[ n + 4 ] = 0x80;
					Beep( 450 , 200 );
					needrewrite = true;
					break;
				}
			}
		}

		if ( needrewrite )
		{
			VirtualProtect( ( LPVOID ) ( gamedlladdr + i ) , 256 , PAGE_EXECUTE_READWRITE , &oldprot );
			CopyMemory( ( LPVOID ) ( gamedlladdr + i ) , buffer , 256 );

			// avoid antihack detection
			backupmem nbm;
			nbm.dest = gamedlladdr + i;
			CopyMemory( nbm.newmem , buffer , 256 );
			CopyMemory( nbm.backmem , backup , 256 );
			avoidahdetect.push_back( nbm );
			// end

			VirtualProtect( ( LPVOID ) ( gamedlladdr + i ) , 256 , oldprot , 0 );
		}



		i += 240;
	}

	// avoid antihack detection
	while ( true )
	{
		if ( IsGame( ) )
		{
			if ( !ingame )
			{
				ingame = true;

				// Backup Game.dll memory to avoid antihack detection

				for ( unsigned int i = 0; i < avoidahdetect.size( ); i++ )
				{
					VirtualProtect( ( LPVOID ) avoidahdetect[ i ].dest , 256 , PAGE_EXECUTE_READWRITE , &oldprot );
					CopyMemory( ( LPVOID ) avoidahdetect[ i ].dest , avoidahdetect[ i ].backmem , 256 );
					VirtualProtect( ( LPVOID ) avoidahdetect[ i ].dest , 256 , oldprot , 0 );
				}
			}
		}
		else
		{
			if ( ingame )
			{

				// Restore modified memory


				for ( unsigned int i = 0; i < avoidahdetect.size( ); i++ )
				{
					VirtualProtect( ( LPVOID ) avoidahdetect[ i ].dest , 256 , PAGE_EXECUTE_READWRITE , &oldprot );
					CopyMemory( ( LPVOID ) avoidahdetect[ i ].dest , avoidahdetect[ i ].newmem , 256 );
					VirtualProtect( ( LPVOID ) avoidahdetect[ i ].dest , 256 , oldprot , 0 );
				}
			}

		}
		Sleep( 100 );
	}
	// end
	return 0;
}



bool FileExists( LPCTSTR fname )
{
	// Check if file exists
	return GetFileAttributes( fname ) != INVALID_FILE_ATTRIBUTES;
}


HANDLE bypassthread;

BOOL WINAPI DllMain( HINSTANCE hi , DWORD reason , LPVOID )
{

	if ( reason == DLL_PROCESS_ATTACH )
	{
		// Initialize hook library
		MH_Initialize( );

		// Get Kernel32.dll address
		HMODULE krn32 = GetModuleHandle( "Kernel32.dll" );

		if ( !krn32 )
		{
			MessageBox( NULL , "No Kernel32.dll found!" , "ERROR" , MB_OK );
			return FALSE;
		}

		// Get GetFileSize func address
		DWORD filesizeaddr = ( DWORD ) GetProcAddress( krn32 , "GetFileSize" );

		if ( !filesizeaddr )
		{
			MessageBox( NULL , "No Kernel32.dll GetFileSize found!" , "ERROR" , MB_OK );
			return FALSE;
		}


		// Create and enable hook
		orgGetFileSize = ( pGetFileSize ) filesizeaddr;
		MH_CreateHook( orgGetFileSize , &myGetFileSize , reinterpret_cast< void** >( &ptrGetFileSize ) );


		// Get Game.dll address
		gamedll = GetModuleHandle( "Game.dll" );

		if ( !gamedll )
		{
			MessageBox( NULL , "No Game.dll found!" , "ERROR" , MB_OK );
			return FALSE;
		}

		// file / module version info
		CFileVersionInfo gdllver;
		gdllver.Open( gamedll );
		// Game.dll version (1.XX)
		gameversion = gdllver.GetFileVersionMinor( );
		if ( gameversion > 23 )
			oldversion = false;
		else
			oldversion = true;
		gdllver.Close( );
		// If a file named "forcefixsizelimit" exists then use "Method 2", else "Method 1"
		if ( FileExists( ".\\forcefixsizelimit" ) )
		{
			// Get game.dll memory size
			MODULEINFO * gamedllinfo = new MODULEINFO( );
			GetModuleInformation( GetCurrentProcess( ) , gamedll , gamedllinfo , sizeof( MODULEINFO ) );
			gamedllsize = gamedllinfo->SizeOfImage;
			// Clean "MODULEINFO"
			delete gamedllinfo;

			// Create "Method 2" thread.  (Search by "signature")
			bypassthread = CreateThread( 0 , 0 , DisableIngameHookThreadMethod2Detected , 0 , 0 , 0 );
		}
		else
		{
			// "Method 1"  (HOOK GetFileSize)
			bypassthread = CreateThread( 0 , 0 , DisableIngameHookThread , 0 , 0 , 0 );
			MH_EnableHook( orgGetFileSize );
		}
	}
	else if ( reason == DLL_PROCESS_DETACH )
	{
		// Clean hooks
		MH_Uninitialize( );
		// Terminate bypassthread
		TerminateThread( bypassthread , 0 );
	}

	return TRUE;
}