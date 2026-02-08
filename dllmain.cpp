#include <Windows.h>
#include <memory>
#include <vector>
#include <Psapi.h>
#include <iostream>

// defined here, cant be asked to make files for now
static void debug_log( const char* str, ... );
std::vector<uint8_t> str_to_bytes( const char* pattern );
bool get_mod_info( const char* mod, uintptr_t& base, uintptr_t& size );
void* find_pattern( const char* mod, const char* pattern );

struct c_hook
{
	void* target {};
	void* hook {};
	uint8_t original_bytes[ 32 ] {}; // JMP rel32
	size_t instruction_size = 0x0;
	void* trampoline {};
};

// hook target
// called often
// even while paused
// on PC_HERO

// add a check prolly for that

// Gothic2.exe+336740 
// 8B 91 B8 01 00 00	

// aob scan

size_t get_instruction_size( uint8_t* instr )
{
	uint8_t op = instr[ 0 ];

	switch ( op )
	{
	case 0x8B: // mov r, r/m
	case 0x89: // mov r/m, r
	case 0x03: // add r, r/m
	case 0x01: // add r/m, r
	case 0x33: // xor r, r/m
	case 0x39: // cmp r/m, r
	case 0x85: // test r, r/m
	//case 0x8D: // lea r32, m
	case 0x0F: // two-byte opcode prefix
		if ( op == 0x0F )
			return 2; // just skip prefix, crude
		return 3;     // rough size for these simple ops
	case 0xB8: // mov eax, imm32
	case 0xE8: // call rel32
	case 0xE9: // jmp rel32
		return 5;
	default:
		return 1; // fallback: assume 1 byte
	}
}

void* make_trampoline( uintptr_t target, const uint8_t* bytes, size_t& copied_bytes )
{
	uint8_t* src = reinterpret_cast< uint8_t* >( target );
	uint8_t* trampoline = ( uint8_t* ) VirtualAlloc( nullptr, copied_bytes + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	if ( !trampoline )
		return nullptr;

	size_t offset = 0;

	while ( offset < copied_bytes )
	{
		uint8_t* instr = src + offset;
		uint8_t  op = instr[ 0 ];

		if ( op == 0xE9 )
			break;

		if ( op == 0xC3 || op == 0xC2 )
			break;

		size_t instr_size = get_instruction_size( instr );
		if ( !instr_size )
		{
			VirtualFree( trampoline, 0, MEM_RELEASE );
			return nullptr;
		}

		memcpy( trampoline + offset, instr, instr_size );
		offset += instr_size;
	}

	uintptr_t jmp_back = target + offset;
	trampoline[ offset ] = 0xE9;
	*reinterpret_cast< int32_t* >( trampoline + offset + 1 ) =
		static_cast< int32_t >( jmp_back - ( reinterpret_cast< uintptr_t >( trampoline ) + offset + 5 ) );

	return trampoline;
}

bool place_hook( c_hook& hook )
{
	// before anything, calculate insturction size
	size_t copied = 0;

	while ( copied < 5 )
	{
		size_t instr_size = get_instruction_size( ( uint8_t* ) hook.target + copied );
		copied += instr_size;
	}
	hook.instruction_size = copied;

	DWORD old_protection {};
	if ( !VirtualProtect( hook.target, hook.instruction_size, PAGE_EXECUTE_READWRITE, &old_protection ) )
	{
		debug_log( "instruction size was: %i", hook.instruction_size );
		debug_log( "place hook fail" );
		return false;
	}

	memcpy_s( hook.original_bytes, hook.instruction_size, hook.target, hook.instruction_size );

	hook.trampoline = make_trampoline( reinterpret_cast< uintptr_t >( hook.target ), hook.original_bytes, hook.instruction_size );
	*reinterpret_cast< uint8_t* >( hook.target ) = 0xE9;
	*reinterpret_cast< uint32_t* >( reinterpret_cast< uintptr_t >( hook.target ) + 1 ) =
		static_cast< uint32_t >( reinterpret_cast< uintptr_t >( hook.hook ) -
			( reinterpret_cast< uintptr_t >( hook.target ) + 5 ) );

	for ( size_t i = 5; i < hook.instruction_size; ++i )
		*reinterpret_cast< uint8_t* >( reinterpret_cast< uintptr_t >( hook.target ) + i ) = 0x90;

	debug_log( "created hook @ 0x%p", hook.target );

	FlushInstructionCache( GetCurrentProcess( ), hook.target, hook.instruction_size );
	VirtualProtect( hook.target, hook.instruction_size, old_protection, &old_protection );
	return true;
}

void restore_hooked_region( const c_hook& hook )
{
	DWORD old_protection {};
	if ( !VirtualProtect( hook.target, hook.instruction_size, PAGE_EXECUTE_READWRITE, &old_protection ) )
	{
		debug_log( "instruction size was: %i", hook.instruction_size );
		debug_log( "restore hook fail" );
		return;
	}

	memcpy_s( hook.target, hook.instruction_size, hook.original_bytes, hook.instruction_size );

	debug_log( "restored hook @ 0x%p", hook.target );
	FlushInstructionCache( GetCurrentProcess( ), hook.target, hook.instruction_size );
	VirtualProtect( hook.target, hook.instruction_size, old_protection, &old_protection );
	return;
}

static c_hook target_loop {};
struct c_base_npc_ex
{
	char padding0x1[ 0x1B8 ];

	int health;
	int health_max;
	int mana_current;
	int mana_max;
	int strength;
	int dexterity;

	char padding0x3[ 10 ];

	int fight_one_hand;
	int fight_two_hand;
	int bow;
	int crossbow;

	char padding0x4[ 4 ];

	int prot_bam;
	int prot_slash;
	int prot_fire; // value / 10
	int prot_fall;
	int prot_magic;
	int prot_pierce;
};

struct c_cheat_config
{
	bool godmode = false;
	bool infite_mana = false;
	bool add_str_dex = false;
	bool add_mana = false;
	bool add_prot = false;
	bool add_prot_fall = false;
	bool add_1000_gold = false;
	
} static cheat_config;

std::atomic_bool changing_config = false;

void apply_godmode( c_base_npc_ex* local )
{
	if ( !local )
		return;

	static int old_health = 0;
	if ( old_health == 0 )
		old_health = local->health_max;

	int delta = local->health - old_health;
	if ( delta > 0 )
	{
		old_health = local->health_max;
		return;
	}

	if ( !cheat_config.godmode )
		return;
	
	if ( delta < 0 )
	{
		local->health = old_health;
		old_health = local->health;
	}
}

void infinite_mana( c_base_npc_ex* local )
{
	if ( !local )
		return;

	static int old_mana = 0;
	if ( old_mana == 0 )
		old_mana = local->health;

	int delta = local->mana_current - old_mana;
	if ( delta > 0 )
	{
		old_mana = local->mana_current;
		return;
	}

	if ( !cheat_config.infite_mana )
		return;

	// our health dropped
	if ( delta < 0 )
	{
		local->mana_current = old_mana;
		old_mana = local->mana_current;
	}
}

void change_attributes( c_base_npc_ex* local )
{
	if ( cheat_config.add_mana )
	{
		int old_max = local->mana_max;

		local->mana_current = local->mana_max = old_max + 10;
		debug_log( "added 10 to mana" );
		cheat_config.add_mana = false;
	}

	if ( cheat_config.add_prot )
	{
		int change = local->prot_bam + 10;
		local->prot_bam = change;

		change = local->prot_fire + 10;
		local->prot_fire = change;

		change = local->prot_magic + 10;
		local->prot_magic = change;

		change = local->prot_slash + 10;
		local->prot_slash = change;

		change = local->prot_pierce + 10;
		local->prot_pierce = change;

		debug_log( "added 10 to prot" );
		cheat_config.add_prot = false;
	}

	if ( cheat_config.add_prot_fall )
	{
		local->prot_fall += 10;
		debug_log( "added 10 to prot fall" );
		cheat_config.add_prot_fall = false;
	}

	if ( cheat_config.add_str_dex )
	{
		int change = local->dexterity + 10;
		local->dexterity = change;

		change = local->strength + 10;
		local->strength = change;

		debug_log( "added 10 to str,dex" );
		cheat_config.add_str_dex = false;
	}
}

void __cdecl character_loop( void* ecx )
{
	auto local = reinterpret_cast< c_base_npc_ex* >( ecx );
	void* offset_p_1 = *reinterpret_cast< void** > ( ( uintptr_t ) ecx + 0x18 );
	if ( offset_p_1 != nullptr && local != nullptr )
	{
		char buffer[ 128 ] = {};
		strcpy_s( buffer, 128, ( const char* ) offset_p_1 );

		// verify this is us
		if ( strcmp( buffer, "PC_HERO" ) == 0 )
		{
			if ( !changing_config.load( ) )
			{
				apply_godmode( local );
				infinite_mana( local );
				change_attributes( local );
			}
		}
	}

	// 0x1B8 = health maybe
	//debug_log( "our health is %i", *reinterpret_cast< int* >( reinterpret_cast< uintptr_t >( ecx ) + 0x1B8 ) );
}

static c_hook display_item_hook {};

struct captured_display_item
{
	uintptr_t address = {};
	int amt = 0;

	captured_display_item( const uintptr_t& address, int amt )
		: address( address ), amt( amt )
	{
	}
};

std::vector<captured_display_item> captured_display_items = {};


void __cdecl display_item_func( uintptr_t display_item_ptr )
{
	// 0x32C = amount of item
	// multiple things can pass thru here

	// ammo
	// gold
	// and smth else

	if ( display_item_ptr )
	{
		//	if ( byte_a == 83 && byte_b == 116  )
		// arrows

		unsigned char byte_b = *reinterpret_cast< unsigned char* >( *reinterpret_cast< uintptr_t* >( display_item_ptr + 0x27C ) + 0x1 );
		int* amount = reinterpret_cast< int* >( ( uintptr_t ) display_item_ptr + 0x32C );

		if ( cheat_config.add_1000_gold )
		{
			if ( byte_b == 179 ) // gold
			{
				*amount += 1000;
				debug_log( "added 1000 gold, new amount: %i", *amount );

				cheat_config.add_1000_gold = false;
			}
		}

		if ( !captured_display_items.empty( ) )
		{
			bool found = false;
			for ( auto& addr : captured_display_items )
			{
				if ( addr.address == display_item_ptr )
				{
					found = true;
					break;
				}
			}

			if ( !found )
				captured_display_items.emplace_back(
					captured_display_item( display_item_ptr,
						*reinterpret_cast< int* >( ( uintptr_t ) display_item_ptr + 0x32C ) ) );
		}
		else
		{
			int* amount = reinterpret_cast< int* >( ( uintptr_t ) display_item_ptr + 0x32C );
			captured_display_items.emplace_back(
				captured_display_item( display_item_ptr, *amount ) );
		}
	}
}

// maybe its a void?
__declspec( naked ) void character_loop_detour( )
{
	__asm
	{
		pushfd
		pushad

		push ecx
		call character_loop
		add esp, 4

		popad
		popfd

		mov edx, [ ecx + 0x1B8 ]

		jmp[ target_loop.trampoline ]
	}
}

__declspec( naked ) void display_item_stub( )
{
	__asm
	{
		pushfd
		pushad

		//push ebx
		mov ebx, [ eax + 0x32C ]

		push eax
		call display_item_func
		add esp, 4

		//pop ebx

		popad
		popfd

		jmp [ display_item_hook.trampoline ]
	}
}

void main( HMODULE mod )
{
	AllocConsole( );
	freopen_s( reinterpret_cast< FILE** >( stdout ), "CONOUT$", "w", stdout );
	freopen_s( reinterpret_cast< FILE** >( stdin ), "CONIN$", "r", stdin );

	debug_log( "loaded" );

	static const char* pattern = "8B 91 B8 01 00 00";
	static const char* pattern2 = "8B 46 04 03 B8 ? ? ? ? 8B 76 08";

	auto address = find_pattern( "Gothic2.exe", pattern );
	if ( address )
	{
		debug_log( "address for loop found: 0x%p", address );
		target_loop.target = address;
		target_loop.hook = reinterpret_cast< void* >( &character_loop_detour );
		if ( place_hook( target_loop ) )
			debug_log( "hook placed" );
	}

	auto display_address = find_pattern( "UNION_ABI.DLL", pattern2 );
	if ( display_address )
	{
		debug_log( "address for display_address found: 0x%p", display_address );
		display_item_hook.target = ( void* ) ( ( uintptr_t ) display_address + 0x3 ); // ADD
		display_item_hook.hook = reinterpret_cast< void* >( &display_item_stub );
		if ( place_hook( display_item_hook ) )
			debug_log( "gold hook placed" );
	}

	while ( !GetAsyncKeyState( VK_END ) )
	{
		debug_log( "options" );
		debug_log( "1 - god | 2 - infinite mana" );
		debug_log( "3 - add 10 (str, dex)" );
		debug_log( "4 - add 10 (mana)" );
		debug_log( "5 - add 10 (prot)" );
		debug_log( "6 - add 10 (prot fall)" );
		debug_log( "7 - add 1000 gold" );
		debug_log( "8 - print display pointers" );

		int option = 0;
		std::cin >> option;

		changing_config.store( true );
		switch ( option )
		{
		case 1: 
			cheat_config.godmode = !cheat_config.godmode; 
			debug_log( "godmode: %s", cheat_config.godmode ? "ON" : "OFF" );
			break;
		case 2:
			cheat_config.infite_mana = !cheat_config.infite_mana;
			debug_log( "infinite mana: %s", cheat_config.infite_mana ? "ON" : "OFF" );
			break;
		case 3:
			cheat_config.add_str_dex = true;
			debug_log( "adding 10 str and dex" );
			break;
		case 4:
			cheat_config.add_mana = true;
			debug_log( "adding 10 mana" );
			break;
		case 5:
			cheat_config.add_prot = true;
			debug_log( "adding 10 prot" );
			break;
		case 6:
			cheat_config.add_prot_fall = true;
			debug_log( "adding 10 prot (fall)" );
			break;
		case 7:
			cheat_config.add_1000_gold = true;
			debug_log( "adding 1000 gold" );
			break;
		case 8:
			debug_log( "displayed item pointers:" );
			for ( auto& addr : captured_display_items )
			{
				debug_log( "0x%p - amount: %i", reinterpret_cast< void* >( addr.address ), addr.amt );
			}
			break;
		}
		changing_config.store( false );

		Sleep( 1 );
	}

	restore_hooked_region( target_loop );
	debug_log( "unloaded" );

	FreeConsole( );
	FreeLibraryAndExitThread( mod, 0 );
}

BOOL APIENTRY DllMain( HMODULE hModule,
					   DWORD  ul_reason_for_call,
					   LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread( nullptr, 0, reinterpret_cast< LPTHREAD_START_ROUTINE >( main ), hModule, 0, nullptr );
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


static void debug_log( const char* str, ... )
{
	va_list args;
	va_start( args, str );
	char buffer[ 512 ];
	vsnprintf_s( buffer, sizeof( buffer ), str, args );
	va_end( args );
	strcat_s( buffer, "\n" );
	printf( buffer );
}

std::vector<uint8_t> str_to_bytes( const char* pattern )
{
	std::vector<uint8_t> temp {};
	size_t len = strlen( pattern );
	for ( size_t i = 0; i < len; i++ )
	{
		if ( pattern[ i ] == ' ' )
			continue;

		if ( pattern[ i ] == '?' )
		{
			temp.emplace_back( 0 );
			if ( pattern[ i + 1 ] == '?' )
				i++;
		}
		else
		{
			char byteString[ 3 ] = { pattern[ i ], pattern[ i + 1 ], 0 };
			temp.emplace_back( static_cast< char >( strtoul( byteString, nullptr, 16 ) ) );
			i++;
		}
	}

	return temp;
}

bool get_mod_info( const char* mod, uintptr_t& base, uintptr_t& size )
{
	HMODULE module = GetModuleHandleA( mod );
	if ( !module )
		return false;

	MODULEINFO info {};
	if ( GetModuleInformation( GetCurrentProcess( ), module, &info, sizeof( MODULEINFO ) ) )
	{
		base = reinterpret_cast< uintptr_t >( info.lpBaseOfDll );
		size = static_cast< uintptr_t >( info.SizeOfImage );
		return true;
	}

	return false;
}

void* find_pattern( const char* mod, const char* pattern )
{
	HMODULE module = GetModuleHandleA( mod );
	if ( !module )
	{
		debug_log( "find pattern a" );
		return nullptr;
	}

	uintptr_t base = 0;
	uintptr_t size = 0;

	if ( !get_mod_info( mod, base, size ) )
	{
		debug_log( "find pattern b" );
		return nullptr;
	}

	debug_log( "module base: 0x%p size: 0x%p", reinterpret_cast< void* >( base ), reinterpret_cast< void* >( size ) );

	auto bytes = str_to_bytes( pattern );
	uint8_t* start = reinterpret_cast< uint8_t* >( base );
	uint8_t* end = start + size - bytes.size( );
	for ( uint8_t* curr = start; curr < end; ++curr )
	{
		bool found = true;
		for ( size_t i = 0; i < bytes.size( ); ++i )
		{
			if ( bytes[ i ] != 0 && curr[ i ] != bytes[ i ] )
			{
				found = false;
				break;
			}
		}

		if ( found )
			return curr;
	}
	return nullptr;
}