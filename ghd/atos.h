
#ifndef ATOS_H
#define ATOS_H


//
// atos code reused from rsvp (https://github.com/blitzcode/rsvp)
//


// Wrapper around atos tool
//
// http://developer.apple.com/library/mac/#documentation/Darwin/Reference/ManPages/man1/atos.1.html
//
// Duplicating the full functionality of this tool would be rather difficult. Its source is not
// available, some of the underlying APIs are poorly documented, plus it does exactly what we need
// and seems reasonably fast and reliable
class ATOS_Pipe
{
public:
    ATOS_Pipe(pid_t pid)
    {
        // Check for atos
        //
        // Since 10.9 calling atos directly seems to be deprecated. The warning suggest
        // to invoke it through xcrun, which seems to work fine on 10.6 already
        //
        // Also see here:
        //
        // http://root.cern.ch/phpBB3/viewtopic.php?f=3&t=17190&start=30
        // https://github.com/allending/Kiwi/pull/365
        if (std::system("xcrun atos 2> /dev/null") != 0)
            assert(!"Can't find 'atos' command line utility - dev. tools not installed?");

        // TODO: The bi-directional popen() only works with this environment
        //       variable set to avoid a deadlock due to buffering, nasty
        if (setenv("NSUnbufferedIO", "YES", 1) != 0)
            assert(!"setenv failed");

        char buf[64];
        std::snprintf(buf, sizeof(buf), "xcrun atos -p %i", pid);
        m_pipe = popen(buf, "r+");
        assert(m_pipe != NULL);
    }

    ~ATOS_Pipe()
    {
        if (m_pipe != NULL)
            if (pclose(m_pipe ) != 0)
                assert(!"pclose() failed");
    }

    void AddressToSymbol(uint64_t addr, char *buf, size_t buf_len) const
    {
        // Communicate with atos program for address resolution, needs to have
        // buffering disabled to not deadlock

        // The addresses need to be in hexadecimal, since 10.7 atos only resolves those
        if (std::fprintf(m_pipe, "0x%llx\n", addr) <= 0)
            assert(!"Writing to atos pipe failed");

        if (std::fgets(buf, buf_len, m_pipe) == NULL)
            assert(!"Reading from atos pipe failed");
    }

protected:
    std::FILE *m_pipe;

};

class SymbolManager
{
public:
    SymbolManager(pid_t pid) :
        m_atos(pid),
        m_cache_hit(0),
        m_cache_miss(0),
        m_unresolved_sym_name("(Unresolved)")
    { }

    uint32_t AddressToSymbolID(
        uint64_t addr,
        uint16_t *file_name_id_out = NULL, // Optional source & line information starts here
        uint16_t *line_number_out  = NULL)
    {
        // Resolve an address into a symbol ID common to all addresses resolving into that symbol.
        // We return source and line information on the spot. We can't cache them here as they are
        // tied to the address and not the symbol

        // Check address cache
        CacheEntry &cache = m_cache[addr % (sizeof(m_cache) / sizeof(CacheEntry))];
        if (cache.m_pc == addr &&
            cache.m_sym_id != uint32_t(-1)) // Sometimes we get a null address and a false hit
        {
            m_cache_hit++;
        }
        else
        {
            m_cache_miss++;

            // Obtain symbol string from atos
            char symbol[8192];
            m_atos.AddressToSymbol(addr, symbol, sizeof(symbol));

            // Module and file name / line
            char module[1024];
            char file_name[1024];
            uint line_number;
            ExtractModuleAndFileName(
                symbol,
                module,
                sizeof(module),
                file_name,
                sizeof(file_name),
                &line_number);

            // De-mangle atos output into clean and display friendly symbol name
            PrettyPrintSymbol(symbol);

            // Just convert all hex addresses to a single unresolved token
            if (std::strncmp(symbol, "0x", 2) == 0)
                std::strncpy(symbol, GetUnresolvedSymbolName(), sizeof(symbol));

            // Check if we already have that symbol name in the table
            const uint64_t sym_hash = BernsteinHash(symbol) ^ BernsteinHash(module);
            std::map<uint64_t, uint32_t>::iterator it_sym = m_hash_to_sym_id.find(sym_hash);
            if (it_sym == m_hash_to_sym_id.end())
            {
                // Add to symbol and module name string table
                uint32_t new_id = uint32_t(m_sym_table.size());
                m_sym_table.push_back(SymbolName());
                m_sym_table.back().m_symbol = std::string(symbol);
                m_sym_table.back().m_module = std::string(module);

                // Hash-to-ID translation entry
                it_sym = m_hash_to_sym_id.insert
                    (std::map<uint64_t, uint32_t>::value_type(sym_hash, new_id)).first;
            }

            // Check if we already have that file name in the table
            const uint64_t file_hash = BernsteinHash(file_name);
            std::map<uint64_t, uint16_t>::iterator it_file = m_hash_to_file_name_id.find(file_hash);
            if (it_file == m_hash_to_file_name_id.end())
            {
                // Add to file name string table
                uint16_t new_id = uint16_t(m_file_name_table.size());
                m_file_name_table.push_back(std::string(file_name));

                // Hash-to-ID translation entry
                it_file = m_hash_to_file_name_id.insert
                    (std::map<uint64_t, uint16_t>::value_type(file_hash, new_id)).first;
            }

            // Update cache
            cache.m_pc = addr;
            cache.m_sym_id = (* it_sym).second;
            cache.m_file_name_id = (* it_file).second;
            cache.m_line_number = line_number;

            assert(std::strcmp(symbol,    SymbolIDToName  ((* it_sym ).second)) == 0);
            assert(std::strcmp(module,    SymbolIDToModule((* it_sym ).second)) == 0);
            assert(std::strcmp(file_name, FileIDToName    ((* it_file).second)) == 0);
        }

        // Return results from cache
        if (file_name_id_out != NULL)
            (* file_name_id_out) = cache.m_file_name_id;
        if (line_number_out != NULL)
            (* line_number_out) = cache.m_line_number;
        const uint32_t sym_id = cache.m_sym_id;

        return sym_id;
    }

    const char * SymbolIDToName(uint32_t id) const
    {
        assert(id < m_sym_table.size());
        return m_sym_table[id].m_symbol.c_str();
    }

    const char * SymbolIDToModule(uint32_t id) const
    {
        assert(id < m_sym_table.size());
        return m_sym_table[id].m_module.c_str();
    }

    const char * FileIDToName(uint16_t id) const
    {
        assert(id < m_file_name_table.size());
        return m_file_name_table[id].c_str();
    }

    float GetCacheHitPercentage() const
    {
        return float(m_cache_hit) / float(m_cache_hit + m_cache_miss) * 100.0f;
    }

    const char * GetUnresolvedSymbolName() const { return m_unresolved_sym_name.c_str(); }

protected:
    ATOS_Pipe m_atos;

    // Address -> Symbol ID cache
    uint m_cache_hit;
    uint m_cache_miss;
    struct CacheEntry
    {
        CacheEntry() : m_pc(0), m_sym_id(-1), m_file_name_id(-1), m_line_number(-1) { }
        uint64_t m_pc;
        uint32_t m_sym_id;
        // Have to store this here instead of the symbol table as they vary by address, not symbol
        uint16_t m_file_name_id;
        uint16_t m_line_number;
    } m_cache[65536 * 32]; // 32MB

    // Table of unique symbol names and map to translate string hash -> table location
    std::map<uint64_t, uint32_t> m_hash_to_sym_id;
    struct SymbolName
    {
        std::string m_symbol;
        std::string m_module;
    };
    std::vector<SymbolName> m_sym_table;

    // Table of unique file names and map to translate string hash -> table location
    std::map<uint64_t, uint16_t> m_hash_to_file_name_id;
    std::vector<std::string> m_file_name_table;

    std::string m_unresolved_sym_name;

    uint64_t BernsteinHash(const char *str_) const
    {
        // The original Bernstein hash eventually had some collisions, this is a simple
        // 64 bit extension of it

        const uint8_t *str = reinterpret_cast<const uint8_t *> (str_);
        uint32_t hash_a = 5381;
        uint32_t hash_b = 5387;
        int c;

        while ((c = *str++))
        {
            hash_a = hash_a * 33 ^ c;
            hash_b = hash_b * 35 ^ c;
        }

        return uint64_t(hash_a) | (uint64_t(hash_b) << 32);
    }

    void ExtractModuleAndFileName(
        const char *sym,
        char *module,
        size_t module_len,
        char *file,
        size_t file_len,
        uint *line_number) const
    {
        // Extract the module and file / line from a symbol string. Can pass NULL for all out
        // parameters to skip them

        // Initialize with failure defaults in case we abort
        if (module != NULL)
            std::strncpy(module, GetUnresolvedSymbolName(), module_len);
        if (file != NULL)
            std::strncpy(file, GetUnresolvedSymbolName(), file_len);
        if (line_number != NULL)
            (* line_number) = 0;

        // Find module name part
        const char module_token[] = " (in ";
        const char *module_begin = std::strstr(sym, module_token);
        if (module_begin == NULL)
            return; // Not present
        module_begin += std::strlen(module_token);

        // Find end of module name part
        const char *module_end = std::strchr(module_begin, ')');
        if (module_end == NULL)
            return; // Must be terminated by closing brace
        const size_t module_idx = module_end - module_begin;

        // Extract module name
        if (module != NULL)
        {
            std::strncpy(module, module_begin, module_len);
            module[std::min(module_idx, module_len)] = '\0';
        }

        // Find file name part
        const char file_token[] = " (";
        const char *file_begin = std::strstr(module_end, file_token);
        if (file_begin == NULL)
            return; // Not present
        file_begin += std::strlen(file_token);

        // Find end of file name part
        const char *file_end = std::strchr(file_begin, ':');
        if (file_end == NULL)
            return; // Need colon
        const size_t file_idx = file_end - file_begin;

        // Extract file name
        if (file != NULL)
        {
            std::strncpy(file, file_begin, file_len);
            file[std::min(file_idx, file_len)] = '\0';
        }

        // Extract line number
        if (line_number != NULL)
            std::sscanf(file_end + 1, "%i", line_number);
    }

    void PrettyPrintSymbol(char *sym) const
    {
        // Convert the output of atos into a name that is readable and compact. We inevitably throw
        // away some information like template arguments, function overloads and module information
        // etc., it's a trade-off. This function also makes certain assumptions on how atos formats
        // its symbols, will likely need to be tweaked if anything changes

        if (sym[0] == '+' || sym[0] == '-')
        {
            // Objective C. We just cut off the parameter list and everything after the brackets
            while (*sym++ != '\0')
            {
                if (*sym == ']' || *sym == ':')
                {
                    *sym++ = ']';
                    *sym = '\0';
                }
            }
        }
        else
        {
            // Assume C / C++

            // Remove module, source file and offset information
            {
                char *cut = std::strstr(sym, " (in ");
                if (cut != NULL)
                    *cut = '\0';
            }

            // Remove newline
            if (sym[std::strlen(sym) - 1] == '\n')
                sym[std::strlen(sym) - 1] = '\0';

            // Shorten '(anonymous namespace)' to 'anon'
            {
                char *anon = NULL;
                const char search[] = "(anonymous namespace)";
                const size_t len_s = sizeof(search) - 1;
                while ((anon = std::strstr(sym, search)))
                {
                    const char replace[] = "anon";
                    const size_t len_r = sizeof(replace) - 1;
                    std::memcpy(anon, replace, len_r);
                    std::memmove(anon + len_r, anon + len_s, std::strlen(sym + len_s) + 1);
                }
            }

            char *orig_ptr = sym;

            // Compact braces and angle brackets
            int angle_level = 0, brace_level = 0;
            char *angle_start = NULL, *brace_start = NULL;
            while (*sym != '\0')
            {
                // Angle brackets confuse our parser, skip operators which have them
                const char ops[][16] =
                {
                    "operator<<=", "operator <<=", "operator>>=", "operator >>=", // Shift Assign
                    "operator<<",  "operator <<",  "operator>>",  "operator >>",  // Shift
                    "operator<",   "operator <",   "operator>",   "operator >",   // Compare
                    "operator->",  "operator ->"                                  // Dereference
                };
                for (uint i=0; i<sizeof(ops) / sizeof(ops[0]); i++)
                    if (std::strncmp(sym, ops[i], std::strlen(ops[i])) == 0)
                    {
                        sym += std::strlen(ops[i]);
                        break;
                    }

                // Don't bother inside braces, we just remove it all anyway
                if (brace_level == 0)
                {
                    // Increment nesting level and store position of first open angle
                    // bracket so we know where to start deleting
                    if (*sym == '<')
                        if (angle_level++ == 0)
                            angle_start = sym;

                    // Decrement nesting level and replace on encountering final angle bracket
                    if (*sym == '>')
                        if (--angle_level == 0)
                        {
                            std::memmove(angle_start + 1, sym, strlen(sym) + 1);
                            sym = angle_start + 1;
                        }
                    assert(angle_level >= 0);
                }

                // Don't bother inside angle brackets, we just remove it all anyway
                if (angle_level == 0)
                {
                    // Increment nesting level and store position of first open
                    // brace so we know where to start deleting
                    if (*sym == '(')
                        if (brace_level++ == 0)
                            brace_start = sym;

                    // Decrement nesting level and delete on encountering final brace
                    if (*sym == ')')
                        if (--brace_level == 0)
                        {
                            if (sym - brace_start > 1)
                            {
                                std::memmove(brace_start + 1, sym, strlen(sym) + 1);
                                sym = brace_start + 1;
                            }
                        }
                    assert(brace_level >= 0);
                }

                sym++;
            }
            assert(angle_level == 0);
            assert(brace_level == 0);

            // Remove leading types and trailing qualifiers
            {
                sym = orig_ptr;

                // Trailing const
                char *const_trail = std::strstr(sym, " const");
                if (const_trail != NULL)
                    *const_trail = '\0';

                // Leading types (return values) are sometimes included in the symbol, remove them
                while (*sym != '\0')
                {
                    // Operator function names have spaces in them, don't throw them
                    // away as leading segments
                    const char ops[][16] = { " operator", ":operator", "$operator" };
                    bool break_outer = false;
                    for (uint i=0; i<sizeof(ops) / sizeof(ops[0]); i++)
                        if (std::strncmp(sym, ops[i], std::strlen(ops[i])) == 0)
                            break_outer = true;
                    if (break_outer)
                        break;

                    // Remove all space separated segments before the last one
                    if (*sym == ' ')
                    {
                        std::memmove(orig_ptr, sym + 1, std::strlen(sym) + 1);
                        sym = orig_ptr;
                        continue;
                    }

                    sym++;
                }
            }
        }
    }
};


#endif // ATOS_H

