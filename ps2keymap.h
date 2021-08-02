/*
 *	Mapping between SDL keysyms and PS/2 keycodes
 */


struct keymapping {
    SDL_Scancode code;
    uint16_t ps2;
};


/* Scan code set 2 */
struct keymapping keytable[] = {
    /* Main keyboard */
    { SDL_SCANCODE_ESCAPE,	0x76 },
    
    { SDL_SCANCODE_F1,		0x05 },
    { SDL_SCANCODE_F2,		0x06 },
    { SDL_SCANCODE_F3,		0x04 },
    { SDL_SCANCODE_F4,		0x0C },
    { SDL_SCANCODE_F5,		0x03 },
    { SDL_SCANCODE_F6,		0x08 },
    { SDL_SCANCODE_F7,		0x83 },
    { SDL_SCANCODE_F8,		0x0A },
    { SDL_SCANCODE_F9,		0x01 },
    { SDL_SCANCODE_F10,		0x09 },
    { SDL_SCANCODE_F11,		0x78 },
    { SDL_SCANCODE_F12,		0x07 },

    /* Print screen is weird */
    { SDL_SCANCODE_SCROLLLOCK,	0x7E },
    /* Pause is weird */
    { SDL_SCANCODE_GRAVE,	0x0E },
    
    { SDL_SCANCODE_1,		0x16 },
    { SDL_SCANCODE_2,		0x1E },
    { SDL_SCANCODE_3,		0x26 },
    { SDL_SCANCODE_4,		0x25 },
    { SDL_SCANCODE_5,		0x2E },
    { SDL_SCANCODE_6,		0x36 },
    { SDL_SCANCODE_7,		0x3D },
    { SDL_SCANCODE_8,		0x3E },
    { SDL_SCANCODE_9,		0x46 },
    { SDL_SCANCODE_0,		0x45 },

    { SDL_SCANCODE_MINUS,	0x4E },
    { SDL_SCANCODE_EQUALS,	0x55 },
    { SDL_SCANCODE_BACKSPACE,	0x66 },
    
    { SDL_SCANCODE_TAB,		0x0D },

    { SDL_SCANCODE_Q,		0x15 },
    { SDL_SCANCODE_W,		0x1D },
    { SDL_SCANCODE_E,		0x24 },
    { SDL_SCANCODE_R,		0x2D },
    { SDL_SCANCODE_T,		0x2C },
    { SDL_SCANCODE_Y,		0x35 },
    { SDL_SCANCODE_U,		0x3C },
    { SDL_SCANCODE_I,		0x43 },
    { SDL_SCANCODE_O,		0x44 },
    { SDL_SCANCODE_P,		0x4D },
    
    { SDL_SCANCODE_LEFTBRACKET,	0x54 },
    { SDL_SCANCODE_RIGHTBRACKET,0x5B },
    { SDL_SCANCODE_BACKSLASH,	0x5D },
    { SDL_SCANCODE_CAPSLOCK,	0x58 },

    { SDL_SCANCODE_A,		0x1C },
    { SDL_SCANCODE_S,		0x1B },
    { SDL_SCANCODE_D,		0x23 },
    { SDL_SCANCODE_F,		0x2B },
    { SDL_SCANCODE_G,		0x34 },
    { SDL_SCANCODE_H,		0x33 },
    { SDL_SCANCODE_J,		0x3B },
    { SDL_SCANCODE_K,		0x42 },
    { SDL_SCANCODE_L,		0x4B },

    { SDL_SCANCODE_SEMICOLON,	0x4C },
    { SDL_SCANCODE_APOSTROPHE,	0x52 },
    { SDL_SCANCODE_RETURN,	0x5A },

    { SDL_SCANCODE_LSHIFT,	0x12 },

    { SDL_SCANCODE_Z,		0x1A },
    { SDL_SCANCODE_X,		0x22 },
    { SDL_SCANCODE_C,		0x21 },
    { SDL_SCANCODE_V,		0x2A },
    { SDL_SCANCODE_B,		0x32 },
    { SDL_SCANCODE_N,		0x31 },
    { SDL_SCANCODE_M,		0x3A },

    { SDL_SCANCODE_COMMA,	0x41 },
    { SDL_SCANCODE_PERIOD,	0x49 },
    { SDL_SCANCODE_SLASH,	0x4A },
    
    { SDL_SCANCODE_RSHIFT,	0x59 },

    { SDL_SCANCODE_LCTRL,	0x14 },
    { SDL_SCANCODE_APPLICATION, 0xE01F },
    { SDL_SCANCODE_LALT,	0x11 },
    { SDL_SCANCODE_SPACE,	0x29 },
    { SDL_SCANCODE_RALT,	0xE011 },
    { SDL_SCANCODE_MENU,	0xE02F },
    { SDL_SCANCODE_RCTRL,	0xE014 },

    /* Cluster above cursor keys */    

    { SDL_SCANCODE_INSERT,	0xE070 },
    { SDL_SCANCODE_HOME,	0xE06C },
    { SDL_SCANCODE_PAGEUP,	0xE07D },
    { SDL_SCANCODE_DELETE,	0xE071 },
    { SDL_SCANCODE_END,		0xE069 },
    { SDL_SCANCODE_PAGEDOWN,	0xE07A },

    /* Arrows */
    
    { SDL_SCANCODE_UP,		0xE075 },
    { SDL_SCANCODE_LEFT,	0xE06B },
    { SDL_SCANCODE_DOWN,	0xE072 },
    { SDL_SCANCODE_RIGHT,	0xE074 },

    /* Number pad */
    
    { SDL_SCANCODE_NUMLOCKCLEAR,0x77 },
    { SDL_SCANCODE_KP_DIVIDE,	0xE04A },
    { SDL_SCANCODE_KP_MULTIPLY,	0x7C },
    { SDL_SCANCODE_KP_MINUS,	0x7B },

    { SDL_SCANCODE_KP_7,	0x6C },
    { SDL_SCANCODE_KP_8,	0x75 },
    { SDL_SCANCODE_KP_9,	0x7D },
    { SDL_SCANCODE_KP_PLUS,	0x79 },
    
    { SDL_SCANCODE_KP_4,	0x6C },
    { SDL_SCANCODE_KP_5,	0x6C },
    { SDL_SCANCODE_KP_6,	0x6C },
    { SDL_SCANCODE_KP_ENTER,	0xE05A },
    
    { SDL_SCANCODE_KP_1,	0x6C },
    { SDL_SCANCODE_KP_2,	0x6C },
    { SDL_SCANCODE_KP_3,	0x6C },

    { SDL_SCANCODE_KP_0,	0x70 },
    { SDL_SCANCODE_KP_PERIOD,	0x71 },

    { SDL_SCANCODE_UNKNOWN,	0 }
};
