#include "pch.h"
#include "recompiler.h"
#include <xex_patcher.h>
#include <switch_tables.h>

static uint64_t ComputeMask(uint32_t mstart, uint32_t mstop)
{
    mstart &= 0x3F;
    mstop &= 0x3F;
    uint64_t value = (UINT64_MAX >> mstart) ^ ((mstop >= 63) ? 0 : UINT64_MAX >> (mstop + 1));
    return mstart <= mstop ? value : ~value;
}

bool Recompiler::LoadConfig(const std::string_view& configFilePath)
{
    config.Load(configFilePath);

    std::vector<uint8_t> file;
    if (!config.patchedFilePath.empty())
        file = LoadFile((config.directoryPath + config.patchedFilePath).c_str());

    if (file.empty())
    {
        file = LoadFile((config.directoryPath + config.filePath).c_str());

        if (!config.patchFilePath.empty())
        {
            const auto patchFile = LoadFile((config.directoryPath + config.patchFilePath).c_str());
            if (!patchFile.empty())
            {
                std::vector<uint8_t> outBytes;
                auto result = XexPatcher::apply(file.data(), file.size(), patchFile.data(), patchFile.size(), outBytes, false);
                if (result == XexPatcher::Result::Success)
                {
                    std::exchange(file, outBytes);

                    if (!config.patchedFilePath.empty())
                    {
                        std::ofstream stream(config.directoryPath + config.patchedFilePath, std::ios::binary);
                        if (stream.good())
                        {
                            stream.write(reinterpret_cast<const char*>(file.data()), file.size());
                            stream.close();
                        }
                    }
                }
                else
                {
                    fmt::print("ERROR: Unable to apply the patch file, ");

                    switch (result)
                    {
                    case XexPatcher::Result::XexFileUnsupported:
                        fmt::println("XEX file unsupported");
                        break;

                    case XexPatcher::Result::XexFileInvalid:
                        fmt::println("XEX file invalid");
                        break;

                    case XexPatcher::Result::PatchFileInvalid:
                        fmt::println("patch file invalid");
                        break;

                    case XexPatcher::Result::PatchIncompatible:
                        fmt::println("patch file incompatible");
                        break;

                    case XexPatcher::Result::PatchFailed:
                        fmt::println("patch failed");
                        break;

                    case XexPatcher::Result::PatchUnsupported:
                        fmt::println("patch unsupported");
                        break;

                    default:
                        fmt::println("reason unknown");
                        break;
                    }

                    return false;
                }
            }
            else
            {
                fmt::println("ERROR: Unable to load the patch file");
                return false;
            }
        }
    }

    image = Image::ParseImage(file.data(), file.size());

    if (config.autoSwitchTables)
    {
        size_t found = 0, added = 0, rejected = 0;
        for (auto type : { SWITCH_ABSOLUTE, SWITCH_COMPUTED, SWITCH_BYTEOFFSET, SWITCH_SHORTOFFSET })
        {
            for (auto& table : FindSwitchTables(image, type))
            {
                found++;
                if (config.switchTables.find(uint32_t(table.base)) != config.switchTables.end())
                    continue;

                // Not reviewed by anyone, so check it. A rejected table that is a real switch is
                // then reported by the "jump table with no switch table entry" problem.
                std::string reason;
                if (!IsPlausibleSwitchTable(image, table, &reason))
                {
                    fmt::println("Switch table at {:X} rejected: {}", table.base, reason);
                    rejected++;
                    continue;
                }

                RecompilerSwitchTable switchTable;
                switchTable.r = table.r;
                for (size_t label : table.labels)
                    switchTable.labels.push_back(uint32_t(label));
                config.switchTables.emplace(uint32_t(table.base), std::move(switchTable));
                added++;
            }
        }
        fmt::println("Switch tables: {} found by pattern, {} added, {} rejected (the rest are in the switch table file)", found, added, rejected);
    }

    return true;
}

void Recompiler::Analyse()
{
    for (size_t i = 14; i < 128; i++)
    {
        if (i < 32)
        {
            if (config.restGpr14Address != 0)
            {
                auto& restgpr = functions.emplace_back();
                restgpr.base = config.restGpr14Address + (i - 14) * 4;
                restgpr.size = (32 - i) * 4 + 12;
                image.symbols.emplace(Symbol{ fmt::format("__restgprlr_{}", i), restgpr.base, restgpr.size, Symbol_Function });
            }

            if (config.saveGpr14Address != 0)
            {
                auto& savegpr = functions.emplace_back();
                savegpr.base = config.saveGpr14Address + (i - 14) * 4;
                savegpr.size = (32 - i) * 4 + 8;
                image.symbols.emplace(fmt::format("__savegprlr_{}", i), savegpr.base, savegpr.size, Symbol_Function);
            }

            if (config.restFpr14Address != 0)
            {
                auto& restfpr = functions.emplace_back();
                restfpr.base = config.restFpr14Address + (i - 14) * 4;
                restfpr.size = (32 - i) * 4 + 4;
                image.symbols.emplace(fmt::format("__restfpr_{}", i), restfpr.base, restfpr.size, Symbol_Function);
            }

            if (config.saveFpr14Address != 0)
            {
                auto& savefpr = functions.emplace_back();
                savefpr.base = config.saveFpr14Address + (i - 14) * 4;
                savefpr.size = (32 - i) * 4 + 4;
                image.symbols.emplace(fmt::format("__savefpr_{}", i), savefpr.base, savefpr.size, Symbol_Function);
            }

            if (config.restVmx14Address != 0)
            {
                auto& restvmx = functions.emplace_back();
                restvmx.base = config.restVmx14Address + (i - 14) * 8;
                restvmx.size = (32 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__restvmx_{}", i), restvmx.base, restvmx.size, Symbol_Function);
            }

            if (config.saveVmx14Address != 0)
            {
                auto& savevmx = functions.emplace_back();
                savevmx.base = config.saveVmx14Address + (i - 14) * 8;
                savevmx.size = (32 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__savevmx_{}", i), savevmx.base, savevmx.size, Symbol_Function);
            }
        }

        if (i >= 64)
        {
            if (config.restVmx64Address != 0)
            {
                auto& restvmx = functions.emplace_back();
                restvmx.base = config.restVmx64Address + (i - 64) * 8;
                restvmx.size = (128 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__restvmx_{}", i), restvmx.base, restvmx.size, Symbol_Function);
            }

            if (config.saveVmx64Address != 0)
            {
                auto& savevmx = functions.emplace_back();
                savevmx.base = config.saveVmx64Address + (i - 64) * 8;
                savevmx.size = (128 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__savevmx_{}", i), savevmx.base, savevmx.size, Symbol_Function);
            }
        }
    }

    for (auto& [address, size] : config.functions)
    {
        functions.emplace_back(address, size);
        image.symbols.emplace(fmt::format("sub_{:X}", address), address, size, Symbol_Function);
    }

    // Switch tables by the address of their bctr (the first bctr at or after the table's base, which
    // is where the code pattern starts), so function extents can include the cases.
    std::unordered_map<size_t, std::vector<size_t>> jumpTables;
    for (const auto& [tableBase, table] : config.switchTables)
    {
        for (const auto& section : image.sections)
        {
            if (!(section.flags & SectionFlags_Code) || tableBase < section.base || tableBase >= section.base + section.size)
                continue;
            for (size_t address = tableBase; address < tableBase + 32 * 4 && address + 4 <= section.base + section.size; address += 4)
            {
                if (ByteSwap(*(uint32_t*)(section.data + address - section.base)) == 0x4E800420) // bctr
                {
                    jumpTables[address].assign(table.labels.begin(), table.labels.end());
                    break;
                }
            }
        }
    }

    // A function whose .pdata entry has ExceptionFlag set is preceded by 8 bytes of exception data
    // (the handler's address and its scope table), not code. Skip them in the linear scan below
    // instead of decoding them as a function.
    std::unordered_set<size_t> exceptionData;

    auto& pdata = *image.Find(".pdata");
    size_t count = pdata.size / sizeof(IMAGE_CE_RUNTIME_FUNCTION);
    auto* pf = (IMAGE_CE_RUNTIME_FUNCTION*)pdata.data;
    for (size_t i = 0; i < count; i++)
    {
        auto fn = pf[i];
        fn.BeginAddress = ByteSwap(fn.BeginAddress);
        fn.Data = ByteSwap(fn.Data);

        if (fn.ExceptionFlag)
            exceptionData.emplace(fn.BeginAddress - 8);

        if (image.symbols.find(fn.BeginAddress) == image.symbols.end())
        {
            auto& f = functions.emplace_back();
            f.base = fn.BeginAddress;
            f.size = fn.FunctionLength * 4;
            pdataFunctions.emplace(f.base, f.size);

            image.symbols.emplace(fmt::format("sub_{:X}", f.base), f.base, f.size, Symbol_Function);
        }
    }

    if (config.dataFunctionStarts)
    {
        std::unordered_set<size_t> switchLabels;
        for (const auto& [tableBase, table] : config.switchTables)
            switchLabels.insert(table.labels.begin(), table.labels.end());

        auto codeWord = [&](size_t address, uint32_t& w) -> bool
            {
                for (const auto& section : image.sections)
                {
                    if ((section.flags & SectionFlags_Code) && section.data != nullptr && address >= section.base + 4 && address + 4 <= section.base + section.size)
                    {
                        w = ByteSwap(*(const uint32_t*)(section.data + address - section.base));
                        return true;
                    }
                }
                return false;
            };

        size_t seeded = 0;
        for (const auto& dataSection : image.sections)
        {
            if ((dataSection.name != ".rdata" && dataSection.name != ".data") || dataSection.data == nullptr)
                continue;
            const uint8_t* imageEnd = image.data.get() + image.size;
            const size_t size = dataSection.data >= imageEnd ? 0 : std::min<size_t>(dataSection.size, imageEnd - dataSection.data);
            for (size_t offset = 0; offset + 4 <= size; offset += 4)
            {
                const size_t target = ByteSwap(*(const uint32_t*)(dataSection.data + offset));
                uint32_t w, previous;
                if ((target & 3) != 0 || switchLabels.count(target) || !codeWord(target, w) || w == 0 || !codeWord(target - 4, previous))
                    continue;
                // Placed like a function start: right after blr, padding or an unconditional b.
                if (!(previous == 0x4E800020 || previous == 0 || (PPC_OP(previous) == PPC_OP_B && !PPC_BL(previous))))
                    continue;
                if (image.symbols.find(target) != image.symbols.end() || image.symbols.findContaining(target) != image.symbols.end())
                    continue; // already known (including import thunks), or inside a .pdata/config function

                for (const auto& section : image.sections)
                {
                    if ((section.flags & SectionFlags_Code) && target >= section.base && target < section.base + section.size)
                    {
                        auto& fn = functions.emplace_back(Function::Analyze(section.data + target - section.base, section.base + section.size - target, target, &jumpTables));
                        image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
                        analysedFunctions.insert(fn.base);
                        ++seeded;
                        break;
                    }
                }
            }
        }
        fmt::println("{} function(s) seeded from code pointers in data", seeded);
    }

    for (const auto& section : image.sections)
    {
        if (!(section.flags & SectionFlags_Code))
        {
            continue;
        }
        size_t base = section.base;
        uint8_t* data = section.data;
        uint8_t* dataEnd = section.data + section.size;

        while (data < dataEnd)
        {
            uint32_t insn = ByteSwap(*(uint32_t*)data);
            if (PPC_OP(insn) == PPC_OP_B && PPC_BL(insn))
            {
                size_t address = base + (data - section.data) + PPC_BI(insn);

                if (address >= section.base && address < section.base + section.size && image.symbols.find(address) == image.symbols.end())
                {
                    auto data = section.data + address - section.base;
                    auto& fn = functions.emplace_back(Function::Analyze(data, section.base + section.size - address, address, &jumpTables));
                    image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
                    analysedFunctions.insert(fn.base);
                }
            }
            data += 4;
        }

        data = section.data;

        while (data < dataEnd)
        {
            if (exceptionData.count(base) && image.symbols.find(base) == image.symbols.end())
            {
                base += 8;
                data += 8;
                continue;
            }

            auto invalidInstr = config.invalidInstructions.find(ByteSwap(*(uint32_t*)data));
            if (invalidInstr != config.invalidInstructions.end())
            {
                base += invalidInstr->second;
                data += invalidInstr->second;
                continue;
            }

            auto fnSymbol = image.symbols.find(base);
            if (fnSymbol != image.symbols.end() && fnSymbol->address == base && fnSymbol->type == Symbol_Function)
            {
                assert(fnSymbol->address == base);

                base += fnSymbol->size;
                data += fnSymbol->size;
            }
            else
            {
                auto& fn = functions.emplace_back(Function::Analyze(data, dataEnd - data, base, &jumpTables));
                image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
                analysedFunctions.insert(fn.base);
                scanFragments.insert(fn.base);

                base += fn.size;
                data += fn.size;
            }
        }
    }

    MergeFragments();
    SplitStrandedFunctions();

    std::sort(functions.begin(), functions.end(), [](auto& lhs, auto& rhs) { return lhs.base < rhs.base; });

    if (!config.emitAnalysisPath.empty())
        EmitAnalysis();
}

void Recompiler::EmitAnalysis()
{
    // A port asked for these files to review or freeze, so a stale or partial one is worse than
    // none: any failure stops the run.
    auto fail = [](const std::string& what)
        {
            fmt::println("ERROR: emit_analysis_path: {}", what);
            std::exit(1);
        };

    const std::filesystem::path directory = std::filesystem::path(config.directoryPath) / config.emitAnalysisPath;
    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
    if (ec)
        fail(fmt::format("can't create {}: {}", directory.string(), ec.message()));

    const std::filesystem::path functionsPath = directory / "functions.toml";
    const std::filesystem::path switchPath = directory / "switch_tables.toml";

    // Never write over the switch table file this run read (its comments would be lost).
    if (!config.switchTableFilePath.empty())
    {
        const std::filesystem::path input = std::filesystem::path(config.directoryPath) / config.switchTableFilePath;
        if (std::filesystem::equivalent(input, switchPath, ec))
            fail(fmt::format("{} is the switch table file this config reads; choose another folder", switchPath.string()));
    }

    {
        std::ofstream stream(functionsPath, std::ios::binary);
        if (!stream)
            fail(fmt::format("can't write {}", functionsPath.string()));
        stream << "# Written by ReXenon (emit_analysis_path): every function that has no .pdata entry, or whose\n";
        stream << "# size differs from it (split at a stranded branch target), as the analysis sized it (bl\n";
        stream << "# targets, the linear scan, data pointers, merges, splits, and config entries). Review it; to\n";
        stream << "# freeze it, put this list in [main] of the port's config, replacing any functions list there\n";
        stream << "# (it already includes those entries).\n";
        stream << "functions = [\n";
        size_t count = 0;
        std::unordered_set<size_t> written;
        for (const auto& fn : functions)
        {
            auto pdata = pdataFunctions.find(fn.base);
            if (pdata != pdataFunctions.end() && pdata->second == fn.size)
                continue;
            // The register save/restore helpers (and anything else the recompiler names itself)
            // come from their own config keys; listing them here would turn them into sub_X.
            auto symbol = image.symbols.find(fn.base);
            if (symbol != image.symbols.end() && symbol->name != fmt::format("sub_{:X}", fn.base))
                continue;
            if (!written.insert(fn.base).second)
                continue; // the config format keeps one entry per address
            stream << fmt::format("    {{ address = 0x{:X}, size = 0x{:X} }},\n", fn.base, fn.size);
            ++count;
        }
        stream << "]\n";
        stream.flush();
        if (!stream)
            fail(fmt::format("writing {} failed", functionsPath.string()));
        fmt::println("Wrote {} function(s) to {}", count, functionsPath.string());
    }

    {
        std::ofstream stream(switchPath, std::ios::binary);
        if (!stream)
            fail(fmt::format("can't write {}", switchPath.string()));
        stream << "# Written by ReXenon (emit_analysis_path): every switch table this run used, from the switch\n";
        stream << "# table file and found automatically. Usable as switch_table_file_path.\n";
        std::vector<uint32_t> bases;
        for (const auto& [tableBase, table] : config.switchTables)
            bases.push_back(tableBase);
        std::sort(bases.begin(), bases.end());
        for (uint32_t tableBase : bases)
        {
            const auto& table = config.switchTables.at(tableBase);
            stream << fmt::format("\n[[switch]]\nbase = 0x{:X}\nr = {}\nlabels = [\n", tableBase, table.r);
            for (uint32_t label : table.labels)
                stream << fmt::format("    0x{:X},\n", label);
            stream << "]\n";
        }
        stream.flush();
        if (!stream)
            fail(fmt::format("writing {} failed", switchPath.string()));
        fmt::println("Wrote {} switch table(s) to {}", config.switchTables.size(), switchPath.string());
    }
}

// A function without a .pdata entry is sized by following its branches, and the analysis drops
// every block after a gap it didn't reach (an exception funclet, a case it couldn't follow). The
// rest of the function then turns up in the linear scan as fragments that its branches jump into.
// Merge them back: a branch from a function that was sized by analysis (not .pdata or config) to
// the middle of a fragment, or a switch case to any part of one, extends the function over it,
// provided every other function in the merged range is a fragment too. A branch to a fragment's
// first instruction is left alone: it can be a tail call to a function only called indirectly.
void Recompiler::MergeFragments()
{
    auto word = [&](size_t address, uint32_t& w) -> bool
        {
            for (const auto& section : image.sections)
            {
                if ((section.flags & SectionFlags_Code) && section.data != nullptr && address >= section.base && address + 4 <= section.base + section.size &&
                    section.data + (address - section.base) + 4 <= image.data.get() + image.size)
                {
                    w = ByteSwap(*(const uint32_t*)(section.data + address - section.base));
                    return true;
                }
            }
            return false;
        };

    // Addresses the program takes the address of: a word in a data section that points into code,
    // or a lis + addi/ori pair in code that builds one. A fragment starting at one of these may be
    // a function reached only through a pointer (a vtable entry, a callback), so it is never
    // absorbed: its entry point has to survive. (Pointers computed some other way aren't seen.)
    auto isCode = [&](size_t address)
        {
            uint32_t w;
            return (address & 3) == 0 && word(address, w);
        };
    // The words of known switch patterns (lis/addi of the table and of the case code's base, from
    // the pattern start up to its bctr).
    std::unordered_set<size_t> switchPatternWords;
    for (const auto& [tableBase, table] : config.switchTables)
    {
        for (size_t address = tableBase; address < tableBase + 32 * 4; address += 4)
        {
            uint32_t w;
            if (!word(address, w))
                break;
            switchPatternWords.insert(address);
            if (w == 0x4E800420) // bctr
                break;
        }
    }

    std::unordered_set<size_t> addressTaken;
    for (const auto& section : image.sections)
    {
        if (section.data == nullptr)
            continue;
        // A section's virtual size can run past the loaded image (a zero-filled tail): stop there.
        const uint8_t* imageEnd = image.data.get() + image.size;
        const size_t size = section.data >= imageEnd ? 0 : std::min<size_t>(section.size, imageEnd - section.data);
        if (!(section.flags & SectionFlags_Code))
        {
            for (size_t offset = 0; offset + 4 <= size; offset += 4)
            {
                const size_t target = ByteSwap(*(const uint32_t*)(section.data + offset));
                if (isCode(target))
                    addressTaken.insert(target);
            }
            continue;
        }
        for (size_t offset = 0; offset + 4 <= size; offset += 4)
        {
            const uint32_t w = ByteSwap(*(const uint32_t*)(section.data + offset));
            const uint32_t op = w >> 26;
            if (op != 14 && op != 24) // addi, ori
                continue;
            if (switchPatternWords.count(section.base + offset))
                continue; // a switch's table or case-code base, not a function pointer
            const uint32_t source = op == 14 ? (w >> 16) & 0x1F : (w >> 21) & 0x1F;
            if (op == 14 && source == 0)
                continue; // li
            for (size_t back = 1; back <= 8 && back * 4 <= offset; back++)
            {
                const uint32_t previous = ByteSwap(*(const uint32_t*)(section.data + offset - back * 4));
                if ((previous >> 26) == 15 && ((previous >> 16) & 0x1F) == 0 && ((previous >> 21) & 0x1F) == source) // lis source
                {
                    const uint32_t high = previous << 16;
                    const size_t target = op == 14 ? uint32_t(high + int32_t(int16_t(w & 0xFFFF))) : (high | (w & 0xFFFF));
                    if (isCode(target))
                        addressTaken.insert(target);
                    break;
                }
            }
        }
    }

    // Case labels sit in .rdata tables too, but they are not entry points.
    for (const auto& [tableBase, table] : config.switchTables)
        for (uint32_t label : table.labels)
            addressTaken.erase(label);

    // (target, from a switch case)
    auto targetsOf = [&](size_t address, std::vector<std::pair<size_t, bool>>& targets)
        {
            uint32_t w;
            if (!word(address, w))
                return;
            if (!PPC_BL(w))
            {
                if (PPC_OP(w) == PPC_OP_B && !PPC_BA(w))
                    targets.emplace_back(address + PPC_BI(w), false);
                else if (PPC_OP(w) == PPC_OP_BC && !PPC_BA(w))
                    targets.emplace_back(address + PPC_BD(w), false);
            }
            auto switchTable = config.switchTables.find(uint32_t(address));
            if (switchTable != config.switchTables.end())
            {
                for (uint32_t label : switchTable->second.labels)
                    targets.emplace_back(label, true);
            }
        };

    auto indexOf = [&](size_t base) -> size_t
        {
            for (size_t i = 0; i < functions.size(); i++)
                if (functions[i].base == base)
                    return i;
            return functions.size();
        };

    size_t merges = 0;
    for (bool changed = true; changed; )
    {
        changed = false;
        for (size_t i = 0; i < functions.size() && !changed; i++)
        {
            if (!analysedFunctions.count(functions[i].base))
                continue;

            const size_t fnBase = functions[i].base;
            const size_t fnEnd = fnBase + functions[i].size;
            std::vector<std::pair<size_t, bool>> targets;
            for (size_t address = fnBase; address < fnEnd; address += 4)
                targetsOf(address, targets);

            for (auto [target, fromSwitch] : targets)
            {
                if ((target >= fnBase && target < fnEnd) || (target & 3) != 0)
                    continue;
                auto containing = image.symbols.findContaining(target);
                if (containing == image.symbols.end() || !scanFragments.count(containing->address))
                    continue;
                if (containing->address == target && !fromSwitch)
                    continue;

                // The merged range runs from the earlier start to the later end. The function at
                // its start keeps its name; a fragment can only be absorbed, never an entry point.
                const size_t start = (std::min)(fnBase, size_t(containing->address));
                const size_t end = (std::max)(fnEnd, size_t(containing->address + containing->size));
                if (start != fnBase && !scanFragments.count(fnBase))
                    continue;

                bool ok = true;
                std::vector<size_t> absorbed;
                for (const auto& f : functions)
                {
                    if (f.base == start || f.base + f.size <= start || f.base >= end)
                        continue;
                    if (f.base < start || !scanFragments.count(f.base) || addressTaken.count(f.base))
                    {
                        ok = false;
                        break;
                    }
                    absorbed.push_back(f.base);
                }
                if (!ok || indexOf(start) == functions.size())
                    continue;

                for (size_t base : absorbed)
                {
                    auto symbol = image.symbols.find(base);
                    if (symbol != image.symbols.end() && symbol->address == base)
                        image.symbols.erase(symbol);
                    const size_t index = indexOf(base);
                    if (index != functions.size())
                        functions.erase(functions.begin() + index);
                    scanFragments.erase(base);
                    analysedFunctions.erase(base);
                }

                const size_t ownerIndex = indexOf(start);
                auto ownerSymbol = image.symbols.find(start);
                const std::string name = ownerSymbol->name;
                image.symbols.erase(ownerSymbol);
                image.symbols.emplace(name, start, end - start, Symbol_Function);
                functions[ownerIndex].size = end - start;
                fmt::println("Merged {} fragment(s) into {} ({:X}-{:X}): {} from {:X} reaches {:X}", absorbed.size(), name, start, end, fromSwitch ? "a switch case" : "a branch", fnBase, target);
                ++merges;
                changed = true;
                break;
            }
        }
    }
    if (merges != 0)
        fmt::println("{} function(s) extended over fragments the analysis cut off", merges);
}

// A branch (b/bc without link, or a switch case) from one function into the middle of another,
// landing right after an instruction that never falls through (b, blr, bctr, or a call to a
// noreturn kernel import), means the second function was sized too far: the target is the start of
// a function of its own, usually an exception funclet or a routine placed after KeBugCheck. Split it
// there, so the branch becomes a tail call instead of an unresolved branch.
// Only when no branch in the part before the target enters the part after it, and none in the part
// after goes back, so each piece is self-contained and no register state flows between them.
void Recompiler::SplitStrandedFunctions()
{
    auto word = [&](size_t address, uint32_t& w) -> bool
        {
            auto* p = (const uint32_t*)image.Find(address);
            if (p == nullptr)
                return false;
            w = ByteSwap(*p);
            return true;
        };

    // Static branch targets of the instruction at address (none for calls and indirect branches).
    auto targetsOf = [&](size_t address, std::vector<size_t>& targets)
        {
            uint32_t w;
            if (!word(address, w))
                return;
            if (!PPC_BL(w))
            {
                if (PPC_OP(w) == PPC_OP_B)
                    targets.push_back(PPC_BA(w) ? size_t(uint32_t(PPC_BI(w))) : address + PPC_BI(w));
                else if (PPC_OP(w) == PPC_OP_BC)
                    targets.push_back(PPC_BA(w) ? size_t(uint32_t(PPC_BD(w))) : address + PPC_BD(w));
            }
            auto switchTable = config.switchTables.find(address);
            if (switchTable != config.switchTables.end())
                targets.insert(targets.end(), switchTable->second.labels.begin(), switchTable->second.labels.end());
        };

    auto neverFallsThrough = [&](size_t address, const char*& why) -> bool
        {
            uint32_t w;
            if (!word(address, w))
                return false;
            if (PPC_OP(w) == PPC_OP_B)
            {
                if (!PPC_BL(w))
                {
                    why = "b";
                    return true;
                }
                const size_t target = PPC_BA(w) ? size_t(uint32_t(PPC_BI(w))) : address + PPC_BI(w);
                auto symbol = image.symbols.find(target);
                if (symbol != image.symbols.end() && symbol->address == target &&
                    (symbol->name == "__imp__KeBugCheck" || symbol->name == "__imp__KeBugCheckEx"))
                {
                    why = "a call to KeBugCheck";
                    return true;
                }
                return false;
            }
            // bclr/bcctr with BO "branch always" and no link
            if (PPC_OP(w) == PPC_OP_CTR && !PPC_BL(w) && (PPC_BO(w) & 0x14) == 0x14)
            {
                if (PPC_XOP(w) == 16)
                {
                    why = "blr";
                    return true;
                }
                if (PPC_XOP(w) == 528)
                {
                    why = "bctr";
                    return true;
                }
            }
            return false;
        };

    size_t splits = 0;
    for (bool changed = true; changed; )
    {
        changed = false;
        for (size_t i = 0; i < functions.size(); i++)
        {
            const size_t fnBase = functions[i].base;
            const size_t fnEnd = fnBase + functions[i].size;

            std::vector<size_t> targets;
            for (size_t address = fnBase; address < fnEnd; address += 4)
                targetsOf(address, targets);

            for (size_t target : targets)
            {
                if ((target >= fnBase && target < fnEnd) || (target & 3) != 0)
                    continue;

                auto exact = image.symbols.find(target);
                if (exact != image.symbols.end() && exact->address == target)
                    continue;

                auto containing = image.symbols.findContaining(target);
                if (containing == image.symbols.end())
                    continue;

                const size_t ownerBase = containing->address;
                const size_t ownerEnd = ownerBase + containing->size;
                const char* why = nullptr;
                if (!neverFallsThrough(target - 4, why))
                    continue;

                size_t owner = functions.size();
                for (size_t j = 0; j < functions.size(); j++)
                {
                    if (functions[j].base == ownerBase && functions[j].base + functions[j].size == ownerEnd)
                    {
                        owner = j;
                        break;
                    }
                }
                if (owner == functions.size())
                    continue;

                bool crossing = false;
                std::vector<size_t> inner;
                for (size_t address = ownerBase; address < ownerEnd && !crossing; address += 4)
                {
                    inner.clear();
                    targetsOf(address, inner);
                    for (size_t t : inner)
                    {
                        const bool fromHead = address < target;
                        if (fromHead ? (t >= target && t < ownerEnd) : (t >= ownerBase && t < target))
                            crossing = true;
                    }
                }
                if (crossing)
                    continue;

                const std::string name = containing->name;
                image.symbols.erase(containing);
                image.symbols.emplace(name, ownerBase, target - ownerBase, Symbol_Function);
                image.symbols.emplace(fmt::format("sub_{:X}", target), target, ownerEnd - target, Symbol_Function);
                functions[owner].size = target - ownerBase;
                functions.emplace_back(target, ownerEnd - target);

                fmt::println("Split {} at {:X} (branched to from {:X}; it follows {})", name, target, fnBase, why);
                ++splits;
                changed = true;
                break;
            }
        }
    }

    if (splits != 0)
        fmt::println("Split {} {} at stranded branch targets", splits, splits == 1 ? "function" : "functions");
}

bool Recompiler::Recompile(
    const Function& fn,
    uint32_t base,
    const ppc_insn& insn,
    const uint32_t* data,
    std::unordered_map<uint32_t, RecompilerSwitchTable>::iterator& switchTable,
    RecompilerLocalVariables& localVariables,
    CSRState& csrState)
{
    println("\t// {} {}", insn.opcode->name, insn.op_str);

    // TODO: we could cache these formats in an array
    auto r = [&](size_t index)
        {
            if ((config.nonArgumentRegistersAsLocalVariables && (index == 0 || index == 2 || index == 11 || index == 12)) || 
                (config.nonVolatileRegistersAsLocalVariables && !emittingInContext && index >= 14))
            {
                localVariables.r[index] = true;
                return fmt::format("r{}", index);
            }
            return fmt::format("ctx.r{}", index);
        };

    auto f = [&](size_t index)
        {
            if ((config.nonArgumentRegistersAsLocalVariables && index == 0) ||
                (config.nonVolatileRegistersAsLocalVariables && !emittingInContext && index >= 14))
            {
                localVariables.f[index] = true;
                return fmt::format("f{}", index);
            }
            return fmt::format("ctx.f{}", index);
        };

    auto v = [&](size_t index)
        {
            if ((config.nonArgumentRegistersAsLocalVariables && (index >= 32 && index <= 63)) ||
                (config.nonVolatileRegistersAsLocalVariables && !emittingInContext && ((index >= 14 && index <= 31) || (index >= 64 && index <= 127))))
            {
                localVariables.v[index] = true;
                return fmt::format("v{}", index);
            }
            return fmt::format("ctx.v{}", index);
        };

    auto cr = [&](size_t index)
        {
            if (config.crRegistersAsLocalVariables)
            {
                localVariables.cr[index] = true;
                return fmt::format("cr{}", index);
            }
            return fmt::format("ctx.cr{}", index);
        };

    auto ctr = [&]()
        {
            if (config.ctrAsLocalVariable)
            {
                localVariables.ctr = true;
                return "ctr";
            }
            return "ctx.ctr";
        };

    auto xer = [&]()
        {
            if (config.xerAsLocalVariable)
            {
                localVariables.xer = true;
                return "xer";
            }
            return "ctx.xer";
        };

    auto reserved = [&]()
        {
            if (config.reservedRegisterAsLocalVariable)
            {
                localVariables.reserved = true;
                return "reserved";
            }
            return "ctx.reserved";
        };

    auto temp = [&]()
        {
            localVariables.temp = true;
            return "temp";
        };

    auto vTemp = [&]()
        {
            localVariables.vTemp = true;
            return "vTemp";
        };

    auto env = [&]()
        {
            localVariables.env = true;
            return "env";
        };

    auto ea = [&]()
        {
            localVariables.ea = true;
            return "ea";
        };

    // Set by printFunctionCall when it inlined a save/restore helper instead of calling it.
    bool callInlined = false;

    // A store followed by eieio is an MMIO store. Don't read past the function's end.
    auto mmioStore = [&]() -> bool
        {
            return base + 4 < fn.base + fn.size && *(data + 1) == c_eieio;
        };

    // inline_register_thunks: recompile the helper's instructions (up to its blr) in place of the
    // call. Returns false, having printed nothing, if the helper isn't straight-line code, if the
    // port hooks it (keep_functions, or a mid-asm hook inside it), or if any of its instructions
    // doesn't recompile (the call then reaches the helper's own function, which traps there).
    auto printInlineThunk = [&](uint32_t address, size_t size, const std::string& name, bool tail) -> bool
        {
            const auto* thunkData = reinterpret_cast<const uint32_t*>(image.Find(address));
            if (thunkData == nullptr || inliningThunk || config.keepFunctions.count(address))
                return false;

            size_t count = 0;
            std::vector<ppc_insn> thunkInsns;
            for (; count < size / 4; ++count)
            {
                const uint32_t word = ByteSwap(thunkData[count]);
                if (config.midAsmHooks.count(uint32_t(address + count * 4))) // the blr's too
                    return false;
                if (word == 0x4E800020) // blr
                    break;
                // Branches, sc and the CR/branch-unit group (op 19) would need labels or a return.
                const uint32_t op = PPC_OP(word);
                if (op == 16 || op == 17 || op == 18 || op == 19)
                    return false;
                auto& thunkInsn = thunkInsns.emplace_back();
                ppc::Disassemble(thunkData + count, 4, address + count * 4, thunkInsn);
                if (thunkInsn.opcode == nullptr)
                    return false;
            }
            if (count == size / 4)
                return false; // no blr inside the helper's extent

            // Undo everything the attempt printed or recorded if an instruction fails.
            const size_t outSize = out.size();
            const size_t problemCount = problems.size();
            const RecompilerLocalVariables savedLocals = localVariables;
            const CSRState savedCsr = csrState;

            println("	// {} (inlined)", name);
            const Function thunkFn(address, (count + 1) * 4);
            auto noSwitch = config.switchTables.end();
            inliningThunk = true;
            thunkInlineTail = tail;
            bool ok = true;
            for (size_t k = 0; k < count && ok; ++k)
                ok = Recompile(thunkFn, uint32_t(address + k * 4), thunkInsns[k], thunkData + k, noSwitch, localVariables, csrState);
            inliningThunk = false;
            thunkInlineTail = false;
            if (!ok)
            {
                out.resize(outSize);
                problems.resize(problemCount);
                localVariables = savedLocals;
                csrState = savedCsr;
            }
            return ok;
        };

    auto printFunctionCall = [&](uint32_t address, bool tail)
        {
            if (address == config.longJmpAddress)
            {
                println("\tlongjmp(*reinterpret_cast<jmp_buf*>(base + {}.u32), {}.s32);", r(3), r(4));
            }
            else if (address == config.setJmpAddress)
            {
                println("\t{} = ctx;", env());
                println("\t{}.s64 = setjmp(*reinterpret_cast<jmp_buf*>(base + {}.u32));", temp(), r(3));
                println("\tif ({}.s64 != 0) ctx = {};", temp(), env());
                println("\t{} = {};", r(3), temp());
            }
            else
            {
                auto targetSymbol = image.symbols.find(address);

                if (targetSymbol != image.symbols.end() && targetSymbol->address == address && targetSymbol->type == Symbol_Function)
                {
                    if (config.nonVolatileRegistersAsLocalVariables && !emittingInContext &&
                        (targetSymbol->name.find("__rest") == 0 || targetSymbol->name.find("__save") == 0))
                    {
                        // The registers are locals: nothing to save or restore. __savegprlr also
                        // stores the return address (r12) at -8(r1); keep that for guest stack walks.
                        if (targetSymbol->name.find("__savegprlr") == 0)
                            println("\tPPC_STORE_U32({}.u32 + -8, {}.u32);", r(1), r(12));
                        callInlined = true;
                    }
                    else if (config.inlineRegisterThunks &&
                        (targetSymbol->name.find("__rest") == 0 || targetSymbol->name.find("__save") == 0) &&
                        printInlineThunk(address, targetSymbol->size, targetSymbol->name, tail))
                    {
                        callInlined = true;
                    }
                    else if (emptyFunctions.count(address))
                    {
                        println("	// {} is only blr", targetSymbol->name);
                    }
                    else if (config.nonVolatileRegistersAsLocalVariables && !emittingInContext &&
                        contextFunctions.count(address))
                    {
                        const NvSet& regs = contextFunctions.at(address);
                        std::vector<std::string> names;
                        for (size_t k = 0; k < 118; ++k)
                        {
                            if (!regs.test(k))
                                continue;
                            if (k < 18) names.push_back(r(k + 14));
                            else if (k < 36) names.push_back(f(k - 18 + 14));
                            else if (k < 54) names.push_back(v(k - 36 + 14));
                            else names.push_back(v(k - 54 + 64));
                        }
                        println("\t{{ // {} keeps these registers in ctx", targetSymbol->name);
                        for (auto& n : names)
                            println("\t\tconst auto saved_{0} = ctx.{0}; ctx.{0} = {0};", n);
                        println("\t\t{}(ctx, base);", targetSymbol->name);
                        for (auto& n : names)
                            println("\t\t{0} = ctx.{0}; ctx.{0} = saved_{0};", n);
                        println("\t}}");
                    }
                    else
                    {
                        println("\t{}(ctx, base);", targetSymbol->name);
                    }
                }
                else
                {
                    // Not a function start: the target is inside another function (a shared epilogue
                    // or a mis-sized function). Trap instead of silently returning.
                    println("\tPPC_UNRESOLVED_BRANCH(0x{:X}, 0x{:X});", base, address);
                    auto containing = image.symbols.findContaining(address);
                    if (containing != image.symbols.end())
                        problem("{:X} (in {:X}): branch to {:X}, which is inside {} ({:X}-{:X})", base, fn.base, address, containing->name, containing->address, containing->address + containing->size);
                    else
                        problem("{:X} (in {:X}): branch to {:X}, which isn't in any function", base, fn.base, address);
                }
            }
        };

    auto printConditionalBranch = [&](bool not_, const std::string_view& cond)
        {
            if (insn.operands[1] < fn.base || insn.operands[1] >= fn.base + fn.size)
            {
                println("\tif ({}{}.{}) {{", not_ ? "!" : "", cr(insn.operands[0]), cond);
                print("\t");
                printFunctionCall(insn.operands[1], true);
                println("\t\treturn;");
                println("\t}}");
            }
            else
            {
                println("\tif ({}{}.{}) goto loc_{:X};", not_ ? "!" : "", cr(insn.operands[0]), cond, insn.operands[1]);
            }
        };

    auto printSetFlushMode = [&](bool enable)
        {
            auto newState = enable ? CSRState::VMX : CSRState::FPU;
            if (csrState != newState)
            {
                auto prefix = enable ? "enable" : "disable";
                auto suffix = csrState != CSRState::Unknown ? "Unconditional" : "";
                println("\tctx.fpscr.{}FlushMode{}();", prefix, suffix);

                csrState = newState;
            }
        };

    // Any bc/bclr/bcctr form without a case of its own (the disassembler has a name for every BO/BI
    // combination: beqctrl, bdnzflr, bsol...), decoded from the instruction's BO and BI fields.
    auto printGenericBranch = [&]() -> bool
        {
            const uint32_t w = ByteSwap(*data);
            const uint32_t op = PPC_OP(w);
            enum class Kind { Bc, Bclr, Bcctr } kind;
            if (op == PPC_OP_BC)
                kind = Kind::Bc;
            else if (op == PPC_OP_CTR && PPC_XOP(w) == 16)
                kind = Kind::Bclr;
            else if (op == PPC_OP_CTR && PPC_XOP(w) == 528)
                kind = Kind::Bcctr;
            else
                return false;

            const uint32_t bo = (w >> 21) & 0x1F;
            const uint32_t bi = (w >> 16) & 0x1F;
            const bool link = (w & 1) != 0;

            // bcctr can't decrement CTR (the form is invalid).
            if (kind == Kind::Bcctr && !(bo & 0x04))
            {
                println("\tPPC_UNIMPLEMENTED(0x{:X}, \"bcctr with BO 0x{:X}\");", base, bo);
                problem("{:X} (in {:X}): bcctr with BO 0x{:X} (decrements CTR, an invalid form)", base, fn.base, bo);
                return true;
            }

            std::string cond;
            if (!(bo & 0x04))
            {
                println("\t--{}.u64;", ctr());
                cond = fmt::format("{}.u32 {} 0", ctr(), (bo & 0x02) ? "==" : "!=");
            }
            if (!(bo & 0x10))
            {
                constexpr const char* bits[] = { "lt", "gt", "eq", "so" };
                std::string test = fmt::format("{}{}.{}", (bo & 0x08) ? "" : "!", cr(bi / 4), bits[bi % 4]);
                cond = cond.empty() ? test : cond + " && " + test;
            }
            if (cond.empty())
                cond = "true";

            if (kind == Kind::Bc)
            {
                const size_t target = (w & 2) ? size_t(uint32_t(PPC_BD(w))) : base + PPC_BD(w);
                if (link && target == base + 4 && cond == "true")
                {
                    // bcl 20,31,$+4: reads the PC into LR.
                    println("\tctx.lr = 0x{:X};", base + 4);
                }
                else if (!link && target >= fn.base && target < fn.base + fn.size)
                {
                    println("\tif ({}) goto loc_{:X};", cond, target);
                }
                else
                {
                    // With LK set, LR is written whether or not the branch is taken.
                    if (link && !config.skipLr)
                        println("\tctx.lr = 0x{:X};", base + 4);
                    println("\tif ({}) {{", cond);
                    print("\t");
                    printFunctionCall(target, !link);
                    if (!link)
                        println("\t\treturn;");
                    println("\t}}");
                    if (link)
                        csrState = CSRState::Unknown;
                }
            }
            else if (kind == Kind::Bclr)
            {
                if (!link)
                {
                    println("\tif ({}) return;", cond);
                }
                else
                {
                    // The target is the old LR; LR is written whether or not the branch is taken.
                    println("\t{{ uint32_t target = ctx.lr; ctx.lr = 0x{:X}; if ({}) PPC_CALL_INDIRECT_FUNC(target); }}", base + 4, cond);
                    csrState = CSRState::Unknown;
                }
            }
            else
            {
                if (link && !config.skipLr)
                    println("\tctx.lr = 0x{:X};", base + 4);
                println("\tif ({}) {{", cond);
                println("\t\tPPC_CALL_INDIRECT_FUNC({}.u32);", ctr());
                if (!link)
                    println("\t\treturn;");
                println("\t}}");
                if (link)
                    csrState = CSRState::Unknown;
            }
            return true;
        };

    // tw/twi/td/tdi and all their aliases, decoded from TO. Games use traps for asserts and debug
    // breaks; on a retail console they raise an exception. PPC_TRAP does nothing unless the port
    // defines it (to log the assert, for example).
    auto printGenericTrap = [&]() -> bool
        {
            const uint32_t w = ByteSwap(*data);
            const uint32_t op = PPC_OP(w);
            bool immediate, doubleword;
            if (op == 3)
                immediate = true, doubleword = false;           // twi
            else if (op == 2)
                immediate = true, doubleword = true;            // tdi
            else if (op == 31 && PPC_XOP(w) == 4)
                immediate = false, doubleword = false;          // tw
            else if (op == 31 && PPC_XOP(w) == 68)
                immediate = false, doubleword = true;           // td
            else
                return false;

            const uint32_t to = (w >> 21) & 0x1F;
            const uint32_t ra = (w >> 16) & 0x1F;
            if (to == 0)
                return true; // never traps

            const char* s = doubleword ? "s64" : "s32";
            const char* u = doubleword ? "u64" : "u32";
            const std::string lhsS = fmt::format("{}.{}", r(ra), s);
            const std::string lhsU = fmt::format("{}.{}", r(ra), u);
            std::string rhsS, rhsU;
            if (immediate)
            {
                const int32_t simm = int16_t(w & 0xFFFF);
                rhsS = doubleword ? fmt::format("int64_t({})", simm) : fmt::format("int32_t({})", simm);
                rhsU = doubleword ? fmt::format("uint64_t(int64_t({}))", simm) : fmt::format("uint32_t({})", simm);
            }
            else
            {
                const uint32_t rb = (w >> 11) & 0x1F;
                rhsS = fmt::format("{}.{}", r(rb), s);
                rhsU = fmt::format("{}.{}", r(rb), u);
            }

            std::string cond;
            auto add = [&](uint32_t bit, const std::string& test)
                {
                    if (to & bit)
                        cond += (cond.empty() ? "" : " || ") + test;
                };
            add(0x10, lhsS + " < " + rhsS);
            add(0x08, lhsS + " > " + rhsS);
            add(0x04, lhsS + " == " + rhsS);
            add(0x02, lhsU + " < " + rhsU);
            add(0x01, lhsU + " > " + rhsU);

            if (to == 0x1F)
                println("\tPPC_TRAP(0x{:X});", base);
            else
                println("\tif ({}) PPC_TRAP(0x{:X});", cond, base);
            return true;
        };

    auto midAsmHook = config.midAsmHooks.find(base);

    auto printMidAsmHook = [&]()
        {
            bool returnsBool = midAsmHook->second.returnOnFalse || midAsmHook->second.returnOnTrue ||
                midAsmHook->second.jumpAddressOnFalse != NULL || midAsmHook->second.jumpAddressOnTrue != NULL;

            print("\t");
            if (returnsBool)
                print("if (");

            print("{}(", midAsmHook->second.name);
            for (auto& reg : midAsmHook->second.registers)
            {
                if (out.back() != '(')
                    out += ", ";

                switch (reg[0])
                {
                case 'c':
                    if (reg == "ctr")
                        out += ctr();
                    else
                        out += cr(std::atoi(reg.c_str() + 2));
                    break;

                case 'x':
                    out += xer();
                    break;

                case 'r':
                    if (reg == "reserved")
                        out += reserved();
                    else
                        out += r(std::atoi(reg.c_str() + 1));
                    break;

                case 'f':
                    if (reg == "fpscr")
                        out += "ctx.fpscr";
                    else
                        out += f(std::atoi(reg.c_str() + 1));
                    break;

                case 'v':
                    out += v(std::atoi(reg.c_str() + 1));
                    break;
                }
            }

            if (returnsBool)
            {
                println(")) {{");

                if (midAsmHook->second.returnOnTrue)
                    println("\t\treturn;");
                else if (midAsmHook->second.jumpAddressOnTrue != NULL)
                    println("\t\tgoto loc_{:X};", midAsmHook->second.jumpAddressOnTrue);

                println("\t}}");

                println("\telse {{");

                if (midAsmHook->second.returnOnFalse)
                    println("\t\treturn;");
                else if (midAsmHook->second.jumpAddressOnFalse != NULL)
                    println("\t\tgoto loc_{:X};", midAsmHook->second.jumpAddressOnFalse);

                println("\t}}");
            }
            else
            {
                println(");");

                if (midAsmHook->second.ret)
                    println("\treturn;");
                else if (midAsmHook->second.jumpAddress != NULL)
                    println("\tgoto loc_{:X};", midAsmHook->second.jumpAddress);
            }
        };

    if (midAsmHook != config.midAsmHooks.end() && !midAsmHook->second.afterInstruction)
        printMidAsmHook();

    int id = insn.opcode->id;

    // Handling instructions that don't disassemble correctly for some reason here
    if (id == PPC_INST_VUPKHSB128 && insn.operands[2] == 0x60) id = PPC_INST_VUPKHSH128;
    else if (id == PPC_INST_VUPKLSB128 && insn.operands[2] == 0x60) id = PPC_INST_VUPKLSH128;

    // O forms set XER[OV] (and the sticky XER[SO]) from the inputs, then do the base operation.
    // Overflow is Xenon's 32-bit-mode one: the exact sum of the sign-extended low words doesn't fit
    // in 32 bits. Divides overflow on a zero divisor or INT_MIN / -1, mulldo on 64 bits.
    {
        auto A = [&]() { return r(insn.operands[1]); };
        auto B = [&]() { return r(insn.operands[2]); };
        auto printOverflow = [&](const std::string& condition)
            {
                println("\t{}.ov = {};", xer(), condition);
                println("\t{}.so |= {}.ov;", xer(), xer());
            };
        auto printOverflow32 = [&](const std::string& wide, const std::string& narrow)
            {
                printOverflow(fmt::format("({}) != int64_t(int32_t({}))", wide, narrow));
            };

        switch (id)
        {
        case PPC_INST_ADDO: printOverflow32(fmt::format("int64_t({}.s32) + {}.s32", A(), B()), fmt::format("{}.u32 + {}.u32", A(), B())); id = PPC_INST_ADD; break;
        case PPC_INST_ADDCO: printOverflow32(fmt::format("int64_t({}.s32) + {}.s32", A(), B()), fmt::format("{}.u32 + {}.u32", A(), B())); id = PPC_INST_ADDC; break;
        case PPC_INST_ADDEO: printOverflow32(fmt::format("int64_t({}.s32) + {}.s32 + {}.ca", A(), B(), xer()), fmt::format("{}.u32 + {}.u32 + {}.ca", A(), B(), xer())); id = PPC_INST_ADDE; break;
        case PPC_INST_ADDMEO: printOverflow32(fmt::format("int64_t({}.s32) + {}.ca - 1", A(), xer()), fmt::format("{}.u32 + {}.ca - 1", A(), xer())); id = PPC_INST_ADDME; break;
        case PPC_INST_ADDZEO: printOverflow32(fmt::format("int64_t({}.s32) + {}.ca", A(), xer()), fmt::format("{}.u32 + {}.ca", A(), xer())); id = PPC_INST_ADDZE; break;
        case PPC_INST_SUBFO: printOverflow32(fmt::format("int64_t({}.s32) - {}.s32", B(), A()), fmt::format("{}.u32 - {}.u32", B(), A())); id = PPC_INST_SUBF; break;
        case PPC_INST_SUBFCO: printOverflow32(fmt::format("int64_t({}.s32) - {}.s32", B(), A()), fmt::format("{}.u32 - {}.u32", B(), A())); id = PPC_INST_SUBFC; break;
        case PPC_INST_SUBFEO: printOverflow32(fmt::format("int64_t(~{}.s32) + {}.s32 + {}.ca", A(), B(), xer()), fmt::format("~{}.u32 + {}.u32 + {}.ca", A(), B(), xer())); id = PPC_INST_SUBFE; break;
        case PPC_INST_SUBFMEO: printOverflow32(fmt::format("int64_t(~{}.s32) + {}.ca - 1", A(), xer()), fmt::format("~{}.u32 + {}.ca - 1", A(), xer())); id = PPC_INST_SUBFME; break;
        case PPC_INST_SUBFZEO: printOverflow32(fmt::format("int64_t(~{}.s32) + {}.ca", A(), xer()), fmt::format("~{}.u32 + {}.ca", A(), xer())); id = PPC_INST_SUBFZE; break;
        case PPC_INST_NEGO: printOverflow(fmt::format("{}.u32 == 0x80000000", A())); id = PPC_INST_NEG; break;
        case PPC_INST_MULLWO: printOverflow32(fmt::format("int64_t({}.s32) * {}.s32", A(), B()), fmt::format("int64_t({}.s32) * {}.s32", A(), B())); id = PPC_INST_MULLW; break;
        case PPC_INST_MULLDO: printOverflow(fmt::format("[&] {{ int64_t p; return __builtin_mul_overflow({}.s64, {}.s64, &p); }}()", A(), B())); id = PPC_INST_MULLD; break;
        case PPC_INST_DIVWO: printOverflow(fmt::format("{1}.s32 == 0 || ({0}.s32 == INT32_MIN && {1}.s32 == -1)", A(), B())); id = PPC_INST_DIVW; break;
        case PPC_INST_DIVWUO: printOverflow(fmt::format("{}.u32 == 0", B())); id = PPC_INST_DIVWU; break;
        case PPC_INST_DIVDO: printOverflow(fmt::format("{1}.s64 == 0 || ({0}.s64 == INT64_MIN && {1}.s64 == -1)", A(), B())); id = PPC_INST_DIVD; break;
        case PPC_INST_DIVDUO: printOverflow(fmt::format("{}.u64 == 0", B())); id = PPC_INST_DIVDU; break;
        }
    }

    // Everything one instruction prints starts here (used by the record-form check after the switch).
    const size_t outStart = out.size();

    switch (id)
    {
    case PPC_INST_VCMPGTSB:
    case PPC_INST_VCMPGTSH:
    case PPC_INST_VCMPGTSW:
    case PPC_INST_VCMPEQUH:
    case PPC_INST_VMAXSB:
    case PPC_INST_VMAXSH:
    case PPC_INST_VMAXUB:
    case PPC_INST_VMAXUH:
    case PPC_INST_VMAXUW:
    case PPC_INST_VMINSB:
    case PPC_INST_VMINSH:
    case PPC_INST_VMINSW:
    case PPC_INST_VMINUB:
    case PPC_INST_VMINUH:
    case PPC_INST_VMINUW:
    case PPC_INST_VADDUHS:
    case PPC_INST_VSUBUHS:
    case PPC_INST_VSUBSBS:
    case PPC_INST_VSUBSHS:
    case PPC_INST_VSUBUBM:
    case PPC_INST_VAVGUH:
    case PPC_INST_VPKSHSS:
    case PPC_INST_VPKSHSS128:
    case PPC_INST_VPKSWUS:
    case PPC_INST_VPKSWUS128:
    {
        // One SSE intrinsic each. Elementwise ops don't care that the vector is stored reversed;
        // packs take vB first (its elements are the low half of the reversed result).
        const char* intrinsic = nullptr;
        bool pack = false;
        switch (id)
        {
        case PPC_INST_VCMPGTSB: intrinsic = "cmpgt_epi8"; break;
        case PPC_INST_VCMPGTSH: intrinsic = "cmpgt_epi16"; break;
        case PPC_INST_VCMPGTSW: intrinsic = "cmpgt_epi32"; break;
        case PPC_INST_VCMPEQUH: intrinsic = "cmpeq_epi16"; break;
        case PPC_INST_VMAXSB: intrinsic = "max_epi8"; break;
        case PPC_INST_VMAXSH: intrinsic = "max_epi16"; break;
        case PPC_INST_VMAXUB: intrinsic = "max_epu8"; break;
        case PPC_INST_VMAXUH: intrinsic = "max_epu16"; break;
        case PPC_INST_VMAXUW: intrinsic = "max_epu32"; break;
        case PPC_INST_VMINSB: intrinsic = "min_epi8"; break;
        case PPC_INST_VMINSH: intrinsic = "min_epi16"; break;
        case PPC_INST_VMINSW: intrinsic = "min_epi32"; break;
        case PPC_INST_VMINUB: intrinsic = "min_epu8"; break;
        case PPC_INST_VMINUH: intrinsic = "min_epu16"; break;
        case PPC_INST_VMINUW: intrinsic = "min_epu32"; break;
        case PPC_INST_VADDUHS: intrinsic = "adds_epu16"; break;
        case PPC_INST_VSUBUHS: intrinsic = "subs_epu16"; break;
        case PPC_INST_VSUBSBS: intrinsic = "subs_epi8"; break;
        case PPC_INST_VSUBSHS: intrinsic = "subs_epi16"; break;
        case PPC_INST_VSUBUBM: intrinsic = "sub_epi8"; break;
        case PPC_INST_VAVGUH: intrinsic = "avg_epu16"; break;
        case PPC_INST_VPKSHSS: case PPC_INST_VPKSHSS128: intrinsic = "packs_epi16"; pack = true; break;
        case PPC_INST_VPKSWUS: case PPC_INST_VPKSWUS128: intrinsic = "packus_epi32"; pack = true; break;
        }
        const auto first = v(insn.operands[pack ? 2 : 1]);
        const auto second = v(insn.operands[pack ? 1 : 2]);
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_{}(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), intrinsic, first, second);
        break;
    }

    case PPC_INST_VAVGUW:
    case PPC_INST_VAVGSW:
    case PPC_INST_VSUBUWS:
    case PPC_INST_VADDCUW:
    case PPC_INST_VSUBCUW:
    case PPC_INST_VRLW:
    case PPC_INST_VRLW128:
    {
        // Word ops without an SSE instruction, element by element.
        for (size_t i = 0; i < 4; i++)
        {
            const auto d = v(insn.operands[0]), a = v(insn.operands[1]), b = v(insn.operands[2]);
            switch (id)
            {
            case PPC_INST_VAVGUW: println("\t{}.u32[{}] = uint32_t((uint64_t({}.u32[{}]) + {}.u32[{}] + 1) >> 1);", d, i, a, i, b, i); break;
            case PPC_INST_VAVGSW: println("\t{}.s32[{}] = int32_t((int64_t({}.s32[{}]) + {}.s32[{}] + 1) >> 1);", d, i, a, i, b, i); break;
            case PPC_INST_VSUBUWS: println("\t{}.u32[{}] = {}.u32[{}] < {}.u32[{}] ? 0 : {}.u32[{}] - {}.u32[{}];", d, i, a, i, b, i, a, i, b, i); break;
            case PPC_INST_VADDCUW: println("\t{}.u32[{}] = uint32_t((uint64_t({}.u32[{}]) + {}.u32[{}]) >> 32);", d, i, a, i, b, i); break;
            case PPC_INST_VSUBCUW: println("\t{}.u32[{}] = {}.u32[{}] >= {}.u32[{}];", d, i, a, i, b, i); break;
            default: println("\t{}.u32[{}] = __builtin_rotateleft32({}.u32[{}], {}.u32[{}] & 0x1F);", d, i, a, i, b, i); break;
            }
        }
        break;
    }

    case PPC_INST_VRLB:
    case PPC_INST_VRLH:
    case PPC_INST_VSLH:
    case PPC_INST_VSRH:
    case PPC_INST_VSRAH:
    case PPC_INST_VSRAB:
    {
        // Per-element shifts and rotates, count from the same element of vB (low bits).
        const bool bytes = id == PPC_INST_VRLB || id == PPC_INST_VSRAB;
        const size_t n = bytes ? 16 : 8;
        const char* u = bytes ? "u8" : "u16";
        const char* sgn = bytes ? "s8" : "s16";
        const uint32_t mask = bytes ? 7 : 15;
        for (size_t i = 0; i < n; i++)
        {
            const auto d = v(insn.operands[0]), a = v(insn.operands[1]), b = v(insn.operands[2]);
            switch (id)
            {
            case PPC_INST_VRLB: println("\t{}.u8[{}] = __builtin_rotateleft8({}.u8[{}], {}.u8[{}] & 7);", d, i, a, i, b, i); break;
            case PPC_INST_VRLH: println("\t{}.u16[{}] = __builtin_rotateleft16({}.u16[{}], {}.u16[{}] & 15);", d, i, a, i, b, i); break;
            case PPC_INST_VSLH: println("\t{}.{}[{}] = {}.{}[{}] << ({}.{}[{}] & {});", d, u, i, a, u, i, b, u, i, mask); break;
            case PPC_INST_VSRH: println("\t{}.{}[{}] = {}.{}[{}] >> ({}.{}[{}] & {});", d, u, i, a, u, i, b, u, i, mask); break;
            default: println("\t{}.{}[{}] = {}.{}[{}] >> ({}.{}[{}] & {});", d, sgn, i, a, sgn, i, b, u, i, mask); break;
            }
        }
        break;
    }

    case PPC_INST_VPKUHUM:
    case PPC_INST_VPKUHUM128:
    case PPC_INST_VPKUWUM:
    case PPC_INST_VPKUWUM128:
    case PPC_INST_VPKUHUS:
    case PPC_INST_VPKUHUS128:
    case PPC_INST_VPKUWUS:
    case PPC_INST_VPKUWUS128:
    case PPC_INST_VPKPX:
    {
        // Packs without an SSE instruction (unsigned in, modulo or unsigned saturation; pixel).
        // vD = pack(vA) || pack(vB) big-endian, so vB fills the low half of the reversed storage.
        // Built in vTemp: vD may be vA or vB.
        const bool halves = id == PPC_INST_VPKUHUM || id == PPC_INST_VPKUHUM128 || id == PPC_INST_VPKUHUS || id == PPC_INST_VPKUHUS128;
        const bool saturate = id == PPC_INST_VPKUHUS || id == PPC_INST_VPKUHUS128 || id == PPC_INST_VPKUWUS || id == PPC_INST_VPKUWUS128;
        const size_t n = halves ? 8 : 4;
        for (size_t i = 0; i < 2 * n; i++)
        {
            const auto src = v(insn.operands[i < n ? 2 : 1]);
            const size_t j = i % n;
            if (id == PPC_INST_VPKPX)
                println("\t{}.u16[{}] = uint16_t((({}.u32[{}] >> 24) & 1) << 15 | (({}.u32[{}] >> 19) & 0x1F) << 10 | (({}.u32[{}] >> 11) & 0x1F) << 5 | (({}.u32[{}] >> 3) & 0x1F));",
                    vTemp(), i, src, j, src, j, src, j, src, j);
            else if (halves && saturate)
                println("\t{}.u8[{}] = {}.u16[{}] > 0xFF ? 0xFF : uint8_t({}.u16[{}]);", vTemp(), i, src, j, src, j);
            else if (halves)
                println("\t{}.u8[{}] = uint8_t({}.u16[{}]);", vTemp(), i, src, j);
            else if (saturate)
                println("\t{}.u16[{}] = {}.u32[{}] > 0xFFFF ? 0xFFFF : uint16_t({}.u32[{}]);", vTemp(), i, src, j, src, j);
            else
                println("\t{}.u16[{}] = uint16_t({}.u32[{}]);", vTemp(), i, src, j);
        }
        println("\t{} = {};", v(insn.operands[0]), vTemp());
        break;
    }

    case PPC_INST_VSPLTISH:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u16, simde_mm_set1_epi16(short({})));", v(insn.operands[0]), int16_t(int32_t(insn.operands[1])));
        break;

    case PPC_INST_VRFIP:
    case PPC_INST_VRFIP128:
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_round_ps(simde_mm_load_ps({}.f32), SIMDE_MM_FROUND_TO_POS_INF | SIMDE_MM_FROUND_NO_EXC));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_ADDC:
        println("\t{}.ca = {}.u32 + {}.u32 < {}.u32;", xer(), r(insn.operands[1]), r(insn.operands[2]), r(insn.operands[1]));
        println("\t{}.u64 = {}.u64 + {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_ADDME:
        // rA + CA - 1 carries unless rA is 0 and CA is 0.
        println("\t{}.u8 = ({}.u32 != 0) | {}.ca;", temp(), r(insn.operands[1]), xer());
        println("\t{}.u64 = {}.u64 + {}.ca - 1;", r(insn.operands[0]), r(insn.operands[1]), xer());
        println("\t{}.ca = {}.u8;", xer(), temp());
        break;

    case PPC_INST_SUBFME:
        // ~rA + CA - 1 carries unless ~rA is 0 and CA is 0.
        println("\t{}.u8 = ({}.u32 != 0xFFFFFFFF) | {}.ca;", temp(), r(insn.operands[1]), xer());
        println("\t{}.u64 = ~{}.u64 + {}.ca - 1;", r(insn.operands[0]), r(insn.operands[1]), xer());
        println("\t{}.ca = {}.u8;", xer(), temp());
        break;

    case PPC_INST_SUBFZE:
        // ~rA + CA carries only when rA is 0 and CA is 1.
        println("\t{}.u8 = ({}.u32 == 0) & {}.ca;", temp(), r(insn.operands[1]), xer());
        println("\t{}.u64 = ~{}.u64 + {}.ca;", r(insn.operands[0]), r(insn.operands[1]), xer());
        println("\t{}.ca = {}.u8;", xer(), temp());
        break;

    case PPC_INST_MULHD:
        println("\t{}.s64 = int64_t((__int128({}.s64) * {}.s64) >> 64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_RLDIC:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {}) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], ComputeMask(insn.operands[3], 63 - insn.operands[2]));
        break;

    case PPC_INST_ROTLD:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {}.u8 & 0x3F);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_RLDCL:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {}.u8 & 0x3F) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), ComputeMask(insn.operands[3], 63));
        break;

    case PPC_INST_RLDCR:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {}.u8 & 0x3F) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), ComputeMask(0, insn.operands[3]));
        break;

    case PPC_INST_RLWNM:
        println("\t{}.u64 = __builtin_rotateleft64({}.u32 | ({}.u64 << 32), {}.u8 & 0x1F) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[1]), r(insn.operands[2]), ComputeMask(insn.operands[3] + 32, insn.operands[4] + 32));
        break;

    case PPC_INST_CRAND:
    case PPC_INST_CRANDC:
    case PPC_INST_CREQV:
    case PPC_INST_CRNAND:
    case PPC_INST_CRNOR:
    case PPC_INST_CROR:
    case PPC_INST_CRORC:
    case PPC_INST_CRXOR:
    case PPC_INST_CRSET:
    case PPC_INST_CRCLR:
    case PPC_INST_CRNOT:
    case PPC_INST_CRMOVE:
    {
        // Decoded from the word: the aliases (crset, crnot, ...) hide some operands.
        constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
        auto bit = [&](uint32_t b) { return fmt::format("{}.{}", cr(b / 4), fields[b % 4]); };
        const uint32_t bt = (insn.instruction >> 21) & 0x1F;
        const uint32_t ba = (insn.instruction >> 16) & 0x1F;
        const uint32_t bb = (insn.instruction >> 11) & 0x1F;
        const char* format = nullptr;
        switch ((insn.instruction >> 1) & 0x3FF)
        {
        case 257: format = "{0} & {1}"; break;     // crand
        case 129: format = "{0} & !{1}"; break;    // crandc
        case 289: format = "{0} == {1}"; break;    // creqv (crset)
        case 225: format = "!({0} & {1})"; break;  // crnand
        case 33: format = "!({0} | {1})"; break;   // crnor (crnot)
        case 449: format = "{0} | {1}"; break;     // cror (crmove)
        case 417: format = "{0} | !{1}"; break;    // crorc
        case 193: format = "{0} ^ {1}"; break;     // crxor (crclr)
        default: return false;
        }
        // Evaluated into temp first: BT may be BA or BB.
        println("\t{}.u8 = {};", temp(), fmt::format(fmt::runtime(format), bit(ba), bit(bb)));
        println("\t{} = {}.u8;", bit(bt), temp());
        break;
    }

    case PPC_INST_MCRF:
        println("\t{} = {};", cr((insn.instruction >> 23) & 7), cr((insn.instruction >> 18) & 7));
        break;

    case PPC_INST_MCRXR:
    {
        const auto field = cr((insn.instruction >> 23) & 7);
        println("\t{}.lt = {}.so;", field, xer());
        println("\t{}.gt = {}.ov;", field, xer());
        println("\t{}.eq = {}.ca;", field, xer());
        println("\t{}.so = 0;", field);
        println("\t{}.so = 0;", xer());
        println("\t{}.ov = 0;", xer());
        println("\t{}.ca = 0;", xer());
        break;
    }

    case PPC_INST_MTCRF:
    case PPC_INST_MTOCRF:
    {
        constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
        const uint32_t fxm = (insn.instruction >> 12) & 0xFF;
        const uint32_t rs = (insn.instruction >> 21) & 0x1F;
        for (size_t i = 0; i < 32; i++)
        {
            if (fxm & (0x80 >> (i / 4)))
                println("\t{}.{} = ({}.u32 & 0x{:X}) != 0;", cr(i / 4), fields[i % 4], r(rs), 1u << (31 - i));
        }
        break;
    }

    case PPC_INST_CMP:
    case PPC_INST_CMPL:
    case PPC_INST_CMPI:
    case PPC_INST_CMPLI:
    {
        // Decoded from the word: L is an optional operand the disassembler may leave out.
        const uint32_t bf = (insn.instruction >> 23) & 7;
        const bool l = (insn.instruction >> 21) & 1;
        const uint32_t ra = (insn.instruction >> 16) & 0x1F;
        const bool isSigned = id == PPC_INST_CMP || id == PPC_INST_CMPI;
        const std::string_view type = isSigned ? (l ? "int64_t" : "int32_t") : (l ? "uint64_t" : "uint32_t");
        const std::string_view field = isSigned ? (l ? "s64" : "s32") : (l ? "u64" : "u32");
        std::string right;
        if (id == PPC_INST_CMP || id == PPC_INST_CMPL)
            right = fmt::format("{}.{}", r((insn.instruction >> 11) & 0x1F), field);
        else if (isSigned)
            right = fmt::format("{}", int16_t(insn.instruction & 0xFFFF));
        else
            right = fmt::format("{}", insn.instruction & 0xFFFF);
        println("\t{}.compare<{}>({}.{}, {}, {});", cr(bf), type, r(ra), field, right, xer());
        break;
    }

    case PPC_INST_LHAU:
    case PPC_INST_LHZU:
    case PPC_INST_LFSU:
    case PPC_INST_LFDU:
    case PPC_INST_STHU:
    case PPC_INST_STFSU:
    case PPC_INST_STFDU:
    case PPC_INST_LBZUX:
    case PPC_INST_LHAUX:
    case PPC_INST_LHZUX:
    case PPC_INST_LWZUX:
    case PPC_INST_LWAUX:
    case PPC_INST_LDUX:
    case PPC_INST_LFSUX:
    case PPC_INST_LFDUX:
    case PPC_INST_STBUX:
    case PPC_INST_STHUX:
    case PPC_INST_STDUX:
    case PPC_INST_STFSUX:
    case PPC_INST_STFDUX:
    {
        // Update forms: EA = rA + d (or rA + rB), access, then rA = EA.
        const bool indexed = id == PPC_INST_LBZUX || id == PPC_INST_LHAUX || id == PPC_INST_LHZUX || id == PPC_INST_LWZUX ||
            id == PPC_INST_LWAUX || id == PPC_INST_LDUX || id == PPC_INST_LFSUX || id == PPC_INST_LFDUX ||
            id == PPC_INST_STBUX || id == PPC_INST_STHUX || id == PPC_INST_STDUX || id == PPC_INST_STFSUX || id == PPC_INST_STFDUX;
        const uint32_t ra = indexed ? insn.operands[1] : insn.operands[2];
        if (indexed)
            println("\t{} = {}.u32 + {}.u32;", ea(), r(ra), r(insn.operands[2]));
        else
            println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(ra));

        const auto t = insn.operands[0];
        switch (id)
        {
        case PPC_INST_LBZUX: println("\t{}.u64 = PPC_LOAD_U8({});", r(t), ea()); break;
        case PPC_INST_LHZU: case PPC_INST_LHZUX: println("\t{}.u64 = PPC_LOAD_U16({});", r(t), ea()); break;
        case PPC_INST_LHAU: case PPC_INST_LHAUX: println("\t{}.s64 = int16_t(PPC_LOAD_U16({}));", r(t), ea()); break;
        case PPC_INST_LWZUX: println("\t{}.u64 = PPC_LOAD_U32({});", r(t), ea()); break;
        case PPC_INST_LWAUX: println("\t{}.s64 = int32_t(PPC_LOAD_U32({}));", r(t), ea()); break;
        case PPC_INST_LDUX: println("\t{}.u64 = PPC_LOAD_U64({});", r(t), ea()); break;
        case PPC_INST_LFSU: case PPC_INST_LFSUX:
            printSetFlushMode(false);
            println("\t{}.u32 = PPC_LOAD_U32({});", temp(), ea());
            println("\t{}.f64 = double({}.f32);", f(t), temp());
            break;
        case PPC_INST_LFDU: case PPC_INST_LFDUX: println("\t{}.u64 = PPC_LOAD_U64({});", f(t), ea()); break;
        case PPC_INST_STBUX: println("\tPPC_STORE_U8({}, {}.u8);", ea(), r(t)); break;
        case PPC_INST_STHU: case PPC_INST_STHUX: println("\tPPC_STORE_U16({}, {}.u16);", ea(), r(t)); break;
        case PPC_INST_STDUX: println("\tPPC_STORE_U64({}, {}.u64);", ea(), r(t)); break;
        case PPC_INST_STFSU: case PPC_INST_STFSUX:
            printSetFlushMode(false);
            println("\t{}.f32 = float({}.f64);", temp(), f(t));
            println("\tPPC_STORE_U32({}, {}.u32);", ea(), temp());
            break;
        case PPC_INST_STFDU: case PPC_INST_STFDUX: println("\tPPC_STORE_U64({}, {}.u64);", ea(), f(t)); break;
        }
        println("\t{}.u32 = {};", r(ra), ea());
        break;
    }

    case PPC_INST_LMW:
    case PPC_INST_STMW:
    {
        // rT..r31 from/to consecutive words at rA + d (rA can't be in the loaded range).
        const uint32_t rt = insn.operands[0];
        print("\t{} = ", ea());
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{};", int32_t(insn.operands[1]));
        for (uint32_t i = rt; i < 32; i++)
        {
            if (id == PPC_INST_LMW)
                println("\t{}.u64 = PPC_LOAD_U32({} + {});", r(i), ea(), (i - rt) * 4);
            else
                println("\tPPC_STORE_U32({} + {}, {}.u32);", ea(), (i - rt) * 4, r(i));
        }
        break;
    }

    case PPC_INST_LSWI:
    case PPC_INST_STSWI:
    {
        // NB bytes (0 = 32) from/to rT, rT+1, ... (wrapping to r0), four per register, big-endian,
        // a partial last register left-justified with zeros.
        const uint32_t nb = insn.operands[2] == 0 ? 32 : insn.operands[2];
        print("\t{} = ", ea());
        if (insn.operands[1] != 0)
            println("{}.u32;", r(insn.operands[1]));
        else
            println("0;");
        for (uint32_t i = 0; i < nb; i++)
        {
            const uint32_t reg = (insn.operands[0] + i / 4) % 32;
            const uint32_t shift = 24 - (i % 4) * 8;
            if (id == PPC_INST_LSWI)
            {
                if (i % 4 == 0)
                    println("\t{}.u64 = 0;", r(reg));
                println("\t{}.u64 |= uint32_t(PPC_LOAD_U8({} + {})) << {};", r(reg), ea(), i, shift);
            }
            else
            {
                println("\tPPC_STORE_U8({} + {}, uint8_t({}.u32 >> {}));", ea(), i, r(reg), shift);
            }
        }
        break;
    }

    case PPC_INST_LDBRX:
        print("\t{}.u64 = __builtin_bswap64(PPC_LOAD_U64(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32));", r(insn.operands[2]));
        break;

    case PPC_INST_STDBRX:
        print("\tPPC_STORE_U64(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, __builtin_bswap64({}.u64));", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_FCTIW:
        // Rounds with the current mode (MXCSR holds the guest's RN), so denormals matter: guest mode.
        printSetFlushMode(false);
        println("\t{}.s64 = ({}.f64 > double(INT_MAX)) ? INT_MAX : simde_mm_cvtsd_si32(simde_mm_load_sd(&{}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[1]));
        break;

    case PPC_INST_FNMADD:
        printSetFlushMode(false);
        println("\t{}.f64 = -({}.f64 * {}.f64 + {}.f64);", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_MTFSB0:
    case PPC_INST_MTFSB1:
    {
        // Only RN (bits 30-31) is modelled; the other FPSCR bits are ignored.
        const uint32_t bt = insn.operands[0];
        if (bt == 30 || bt == 31)
        {
            const uint32_t mask = 1u << (31 - bt);
            if (id == PPC_INST_MTFSB1)
                println("\tctx.fpscr.storeFromGuest(uint32_t(ctx.fpscr.loadFromHost()) | 0x{:X});", mask);
            else
                println("\tctx.fpscr.storeFromGuest(uint32_t(ctx.fpscr.loadFromHost()) & ~0x{:X});", mask);
        }
        break;
    }

    case PPC_INST_MTFSFI:
        // Field 7 holds RN (the only modelled part); W (ISA 2.05) doesn't exist on Xenon.
        if (insn.operands[0] == 7)
            println("\tctx.fpscr.storeFromGuest({});", insn.operands[1] & 0xF);
        break;

    case PPC_INST_MCRFS:
    {
        const auto field = cr(insn.operands[0]);
        const uint32_t shift = 4 * (7 - insn.operands[1]);
        println("\t{}.u32 = uint32_t(ctx.fpscr.loadFromHost()) >> {};", temp(), shift);
        println("\t{}.lt = ({}.u32 >> 3) & 1;", field, temp());
        println("\t{}.gt = ({}.u32 >> 2) & 1;", field, temp());
        println("\t{}.eq = ({}.u32 >> 1) & 1;", field, temp());
        println("\t{}.so = {}.u32 & 1;", field, temp());
        break;
    }

    case PPC_INST_MFVSCR:
        // VSCR isn't modelled: NJ (non-Java mode, denormals flushed) is what the console runs with.
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_set_epi32(0, 0, 0, 0x00010000));", v(insn.operands[0]));
        break;

    case PPC_INST_MTVSCR:
        // VSCR isn't modelled (vector code always runs with NJ set).
        break;

    case PPC_INST_ICBI:
    case PPC_INST_DCBI:
        // Cache management: nothing to do.
        break;

    case PPC_INST_STVEBX:
        print("\t{} = ", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\tPPC_STORE_U8({}, {}.u8[15 - ({} & 0xF)]);", ea(), v(insn.operands[0]), ea());
        break;

    case PPC_INST_MFXER:
        println("\t{}.u64 = (uint32_t({}.so) << 31) | (uint32_t({}.ov) << 30) | (uint32_t({}.ca) << 29);", r(insn.operands[0]), xer(), xer(), xer());
        break;

    case PPC_INST_MFCTR:
        println("\t{}.u64 = {}.u64;", r(insn.operands[0]), ctr());
        break;

    case PPC_INST_MFSPR:
    case PPC_INST_MTSPR:
    {
        // The SPR field's halves are swapped in the word.
        const uint32_t sprField = (insn.instruction >> 11) & 0x3FF;
        const uint32_t spr = ((sprField & 0x1F) << 5) | (sprField >> 5);
        const uint32_t reg = (insn.instruction >> 21) & 0x1F;
        if (id == PPC_INST_MFSPR)
        {
            switch (spr)
            {
            case 1: println("\t{}.u64 = (uint32_t({}.so) << 31) | (uint32_t({}.ov) << 30) | (uint32_t({}.ca) << 29);", r(reg), xer(), xer(), xer()); break;
            case 8: if (!config.skipLr) println("\t{}.u64 = ctx.lr;", r(reg)); break;
            case 9: println("\t{}.u64 = {}.u64;", r(reg), ctr()); break;
            case 256: println("\t{}.u64 = 0;", r(reg)); break; // VRSAVE (not modelled)
            case 268: println("\t{}.u64 = PPC_MFTB();", r(reg)); break;
            case 269: println("\t{}.u64 = PPC_MFTB() >> 32;", r(reg)); break;
            default: return false;
            }
        }
        else
        {
            switch (spr)
            {
            case 1:
                println("\t{}.so = ({}.u64 & 0x80000000) != 0;", xer(), r(reg));
                println("\t{}.ov = ({}.u64 & 0x40000000) != 0;", xer(), r(reg));
                println("\t{}.ca = ({}.u64 & 0x20000000) != 0;", xer(), r(reg));
                break;
            case 8: if (!config.skipLr) println("\tctx.lr = {}.u64;", r(reg)); break;
            case 9: println("\t{}.u64 = {}.u64;", ctr(), r(reg)); break;
            case 256: break; // VRSAVE (not modelled)
            default: return false;
            }
        }
        break;
    }

    case PPC_INST_ADD:
        println("\t{}.u64 = {}.u64 + {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDE:
        println("\t{}.u8 = ({}.u32 + {}.u32 < {}.u32) | ({}.u32 + {}.u32 + {}.ca < {}.ca);", temp(), r(insn.operands[1]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[1]), r(insn.operands[2]), xer(), xer());
        println("\t{}.u64 = {}.u64 + {}.u64 + {}.ca;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        println("\t{}.ca = {}.u8;", xer(), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDI:
        print("\t{}.s64 = ", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.s64 + ", r(insn.operands[1]));
        println("{};", int32_t(insn.operands[2]));
        break;

    case PPC_INST_ADDIC:
        println("\t{}.ca = {}.u32 > {};", xer(), r(insn.operands[1]), ~insn.operands[2]);
        println("\t{}.s64 = {}.s64 + {};", r(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDIS:
        print("\t{}.s64 = ", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.s64 + ", r(insn.operands[1]));
        println("{};", static_cast<int32_t>(insn.operands[2] << 16));
        break;

    case PPC_INST_ADDZE:
        println("\t{}.s64 = {}.s64 + {}.ca;", temp(), r(insn.operands[1]), xer());
        println("\t{}.ca = {}.u32 < {}.u32;", xer(), temp(), r(insn.operands[1]));
        println("\t{}.s64 = {}.s64;", r(insn.operands[0]), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_AND:
        println("\t{}.u64 = {}.u64 & {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ANDC:
        println("\t{}.u64 = {}.u64 & ~{}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ANDI:
        println("\t{}.u64 = {}.u64 & {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ANDIS:
        println("\t{}.u64 = {}.u64 & {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2] << 16);
        println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ATTN:
        // undefined instruction
        break;

    case PPC_INST_B:
        if (insn.operands[0] < fn.base || insn.operands[0] >= fn.base + fn.size)
        {
            printFunctionCall(insn.operands[0], true);
            println("\treturn;");
        }
        else
        {
            println("\tgoto loc_{:X};", insn.operands[0]);
        }
        break;

    case PPC_INST_BCTR:
        if (switchTable != config.switchTables.end())
        {
            // The table is indexed by the low word (rlwinm), as the bounds check compares it (cmplwi): a
            // register whose upper half isn't zero (0xFFFFFFFF + 1) still selects its case on the console.
            println("\tswitch ({}.u32) {{", r(switchTable->second.r));

            for (size_t i = 0; i < switchTable->second.labels.size(); i++)
            {
                println("\tcase {}:", i);
                auto label = switchTable->second.labels[i];
                if (label < fn.base || label >= fn.base + fn.size)
                {
                    println("\t\tPPC_UNRESOLVED_BRANCH(0x{:X}, 0x{:X});", base, label);
                    problem("{:X} (in {:X}): switch case {} jumps outside the function, to {:X}", base, fn.base, i, label);
                    println("\t\treturn;");
                }
                else
                {
                    println("\t\tgoto loc_{:X};", label);
                }
            }

            println("\tdefault:");
            println("\t\tPPC_SWITCH_MISS(0x{:X}, {}.u32);", base, r(switchTable->second.r));
            println("\t\treturn;");
            println("\t}}");

            switchTable = config.switchTables.end();
        }
        else
        {
            println("\tPPC_CALL_INDIRECT_FUNC({}.u32);", ctr());
            println("\treturn;");
        }
        break;

    case PPC_INST_BCTRL:
        if (!config.skipLr)
            println("\tctx.lr = 0x{:X};", base + 4);
        println("\tPPC_CALL_INDIRECT_FUNC({}.u32);", ctr());
        csrState = CSRState::Unknown; // the call could change it
        break;

    case PPC_INST_BDZ:
        println("\t--{}.u64;", ctr());
        println("\tif ({}.u32 == 0) goto loc_{:X};", ctr(), insn.operands[0]);
        break;

    case PPC_INST_BDZLR:
        println("\t--{}.u64;", ctr());
        println("\tif ({}.u32 == 0) return;", ctr(), insn.operands[0]);
        break;

    case PPC_INST_BDNZ:
        println("\t--{}.u64;", ctr());
        println("\tif ({}.u32 != 0) goto loc_{:X};", ctr(), insn.operands[0]);
        break;

    case PPC_INST_BDNZT:
    {
        constexpr const char* bits[] = { "lt", "gt", "eq", "so" };
        println("	--{}.u64;", ctr());
        println("	if ({}.u32 != 0 && {}.{}) goto loc_{:X};", ctr(), cr(insn.operands[0] / 4), bits[insn.operands[0] % 4], insn.operands[1]);
        break;
    }

    case PPC_INST_BEQ:
        printConditionalBranch(false, "eq");
        break;

    case PPC_INST_BEQLR:
        println("\tif ({}.eq) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BGE:
        printConditionalBranch(true, "lt");
        break;

    case PPC_INST_BGELR:
        println("\tif (!{}.lt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BGT:
        printConditionalBranch(false, "gt");
        break;

    case PPC_INST_BGTLR:
        println("\tif ({}.gt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BL:
    {
        const size_t lrStart = out.size();
        if (!config.skipLr)
            println("\tctx.lr = 0x{:X};", base + 4);
        const size_t lrEnd = out.size();
        callInlined = false;
        printFunctionCall(insn.operands[0], false);
        // elide_return_lr: an inlined save/restore helper never reads LR, so its return address is
        // dead unless the function reads LR again. Any mflr later in the function (whatever path
        // reaches it) keeps the store. Diagnostics may see a stale LR.
        if (callInlined && config.elideReturnLr && !config.skipLr && !inliningThunk)
        {
            bool lrRead = false;
            for (uint32_t a = base + 4; a < fn.base + fn.size && !lrRead; a += 4)
            {
                const auto* p = reinterpret_cast<const uint32_t*>(image.Find(a));
                if (p == nullptr)
                    break;
                lrRead = (ByteSwap(*p) & 0xFC1FFFFF) == 0x7C0802A6; // mflr
            }
            if (!lrRead)
                out.replace(lrStart, lrEnd - lrStart, "\t// ctx.lr not stored: helper inlined\n");
        }
        if (!emptyFunctions.count(insn.operands[0]))
            csrState = CSRState::Unknown; // the call could change it
        break;
    }

    case PPC_INST_BLE:
        printConditionalBranch(true, "gt");
        break;

    case PPC_INST_BLELR:
        println("\tif (!{}.gt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BLR:
        println("\treturn;");
        break;

    case PPC_INST_BLRL:
        // An indirect call through LR (mtlr rX; blrl): call LR's target, with LR the return address.
        println("	{{ uint32_t target = ctx.lr; ctx.lr = 0x{:X}; PPC_CALL_INDIRECT_FUNC(target); }}", base + 4);
        csrState = CSRState::Unknown; // the call could change it
        break;

    case PPC_INST_BLT:
        printConditionalBranch(false, "lt");
        break;

    case PPC_INST_BLTLR:
        println("\tif ({}.lt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BNE:
        printConditionalBranch(true, "eq");
        break;

    case PPC_INST_BNECTR:
        println("\tif (!{}.eq) {{", cr(insn.operands[0]));
        println("\t\tPPC_CALL_INDIRECT_FUNC({}.u32);", ctr());
        println("\t\treturn;");
        println("\t}}");
        break;

    case PPC_INST_BNELR:
        println("\tif (!{}.eq) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_CCTPL:
        // no op
        break;

    case PPC_INST_CCTPM:
        // no op
        break;

    case PPC_INST_CLRLDI:
        println("\t{}.u64 = {}.u64 & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), (1ull << (64 - insn.operands[2])) - 1);
        break;

    case PPC_INST_CLRLWI:
        println("\t{}.u64 = {}.u32 & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), (1ull << (32 - insn.operands[2])) - 1);
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_CMPD:
        println("\t{}.compare<int64_t>({}.s64, {}.s64, {});", cr(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPDI:
        println("\t{}.compare<int64_t>({}.s64, {}, {});", cr(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPLD:
        println("\t{}.compare<uint64_t>({}.u64, {}.u64, {});", cr(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPLDI:
        println("\t{}.compare<uint64_t>({}.u64, {}, {});", cr(insn.operands[0]), r(insn.operands[1]), insn.operands[2], xer());
        break;

    case PPC_INST_CMPLW:
        println("\t{}.compare<uint32_t>({}.u32, {}.u32, {});", cr(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPLWI:
        println("\t{}.compare<uint32_t>({}.u32, {}, {});", cr(insn.operands[0]), r(insn.operands[1]), insn.operands[2], xer());
        break;

    case PPC_INST_CMPW:
        println("\t{}.compare<int32_t>({}.s32, {}.s32, {});", cr(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPWI:
        println("\t{}.compare<int32_t>({}.s32, {}, {});", cr(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]), xer());
        break;

    case PPC_INST_CNTLZD:
        println("\t{0}.u64 = {1}.u64 == 0 ? 64 : __builtin_clzll({1}.u64);", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_CNTLZW:
        println("\t{0}.u64 = {1}.u32 == 0 ? 32 : __builtin_clz({1}.u32);", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_DB16CYC:
        // no op
        break;

    case PPC_INST_DCBF:
    case PPC_INST_DCBST:
        // no op
        break;

    case PPC_INST_DCBT:
        // no op
        break;

    case PPC_INST_DCBTST:
        // no op
        break;

    case PPC_INST_DCBZ:
        // Xenon's cache line is 128 bytes and plain dcbz clears all of it (32 bytes is the G2/603e line).
        print("\tmemset(base + ((");
        if (insn.operands[0] != 0)
            print("{}.u32 + ", r(insn.operands[0]));
        println("{}.u32) & ~127), 0, 128);", r(insn.operands[1]));
        break;

    case PPC_INST_DCBZL:
        print("\tmemset(base + ((");
        if (insn.operands[0] != 0)
            print("{}.u32 + ", r(insn.operands[0]));
        println("{}.u32) & ~127), 0, 128);", r(insn.operands[1]));
        break;

    case PPC_INST_DIVD:
        // PowerPC divides never trap: zero divisors and overflow give an undefined result.
        println("\t{}.s64 = ({}.s64 == 0 || ({}.s64 == INT64_MIN && {}.s64 == -1)) ? 0 : {}.s64 / {}.s64;", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_DIVDU:
        println("\t{}.u64 = {}.u64 == 0 ? 0 : {}.u64 / {}.u64;", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_DIVW:
        println("\t{}.s32 = ({}.s32 == 0 || ({}.s32 == INT32_MIN && {}.s32 == -1)) ? 0 : {}.s32 / {}.s32;", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_DIVWU:
        println("\t{}.u32 = {}.u32 == 0 ? 0 : {}.u32 / {}.u32;", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_EIEIO:
        println("\tPPC_EIEIO();");
        break;

    case PPC_INST_EXTSB:
        println("\t{}.s64 = {}.s8;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_EXTSH:
        println("\t{}.s64 = {}.s16;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_EXTSW:
        println("\t{}.s64 = {}.s32;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_FABS:
        // Mode-neutral: bit copies, sign-bit ops, exact int->double, truncations to integer. Neither
        // flush-to-zero nor denormals-are-zero changes the result, so the FP mode isn't switched.
        println("\t{}.u64 = {}.u64 & ~0x8000000000000000;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FADD:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 + {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FADDS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 + {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FCFID:
        // Mode-neutral: bit copies, sign-bit ops, exact int->double, truncations to integer. Neither
        // flush-to-zero nor denormals-are-zero changes the result, so the FP mode isn't switched.
        println("\t{}.f64 = double({}.s64);", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FCMPU:
    case PPC_INST_FCMPO: // the same compare; FPSCR exception bits aren't modelled
        printSetFlushMode(false);
        println("\t{}.compare({}.f64, {}.f64);", cr(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FCTID:
        printSetFlushMode(false);
        println("\t{}.s64 = ({}.f64 >= double(LLONG_MAX)) ? LLONG_MAX : simde_mm_cvtsd_si64(simde_mm_load_sd(&{}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[1]));
        break;

    case PPC_INST_FCTIDZ:
        // Mode-neutral: bit copies, sign-bit ops, exact int->double, truncations to integer. Neither
        // flush-to-zero nor denormals-are-zero changes the result, so the FP mode isn't switched.
        println("\t{}.s64 = ({}.f64 >= double(LLONG_MAX)) ? LLONG_MAX : simde_mm_cvttsd_si64(simde_mm_load_sd(&{}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[1]));
        break;

    case PPC_INST_FCTIWZ:
        // Mode-neutral: bit copies, sign-bit ops, exact int->double, truncations to integer. Neither
        // flush-to-zero nor denormals-are-zero changes the result, so the FP mode isn't switched.
        println("\t{}.s64 = ({}.f64 > double(INT_MAX)) ? INT_MAX : simde_mm_cvttsd_si32(simde_mm_load_sd(&{}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[1]));
        break;

    case PPC_INST_FDIV:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 / {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FDIVS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 / {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FMADD:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 * {}.f64 + {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FMADDS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 * {}.f64 + {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FMR:
        // Mode-neutral: bit copies, sign-bit ops, exact int->double, truncations to integer. Neither
        // flush-to-zero nor denormals-are-zero changes the result, so the FP mode isn't switched.
        println("\t{}.f64 = {}.f64;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FMSUB:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 * {}.f64 - {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FMSUBS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 * {}.f64 - {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FMUL:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 * {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FMULS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 * {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FNABS:
        // Mode-neutral: bit copies, sign-bit ops, exact int->double, truncations to integer. Neither
        // flush-to-zero nor denormals-are-zero changes the result, so the FP mode isn't switched.
        println("\t{}.u64 = {}.u64 | 0x8000000000000000;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FNEG:
        // Mode-neutral: bit copies, sign-bit ops, exact int->double, truncations to integer. Neither
        // flush-to-zero nor denormals-are-zero changes the result, so the FP mode isn't switched.
        println("\t{}.u64 = {}.u64 ^ 0x8000000000000000;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FNMADDS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float(-({}.f64 * {}.f64 + {}.f64)));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FNMSUB:
        printSetFlushMode(false);
        println("\t{}.f64 = -({}.f64 * {}.f64 - {}.f64);", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FNMSUBS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float(-({}.f64 * {}.f64 - {}.f64)));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FRSQRTE:
        if (config.exactEstimates)
        {
            // Integer table lookup: the FP mode doesn't matter.
            println("\t{}.u64 = ppc_frsqrte({}.u64);", f(insn.operands[0]), f(insn.operands[1]));
            break;
        }
        printSetFlushMode(false);
        println("	{}.f64 = 1.0 / sqrt({}.f64);", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FRES:
        printSetFlushMode(false);
        println("\t{}.f64 = float(1.0 / {}.f64);", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FRSP:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64));", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FSEL:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 >= 0.0 ? {}.f64 : {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FSQRT:
        printSetFlushMode(false);
        println("\t{}.f64 = sqrt({}.f64);", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FSQRTS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float(sqrt({}.f64)));", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FSUB:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 - {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FSUBS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 - {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_LBZ:
        print("\t{}.u64 = PPC_LOAD_U8(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LBZU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U8({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_LBZX:
        print("\t{}.u64 = PPC_LOAD_U8(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LD:
        print("\t{}.u64 = PPC_LOAD_U64(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LDARX:
        print("\t{}.u64 = PPC_GUEST_LOAD(uint64_t, base + ", reserved());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        println("\t{}.u64 = __builtin_bswap64({}.u64);", r(insn.operands[0]), reserved());
        break;

    case PPC_INST_LDU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U64({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_LDX:
        print("\t{}.u64 = PPC_LOAD_U64(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LFD:
        // Mode-neutral: bit copies, sign-bit ops, exact int->double, truncations to integer. Neither
        // flush-to-zero nor denormals-are-zero changes the result, so the FP mode isn't switched.
        print("\t{}.u64 = PPC_LOAD_U64(", f(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LFDX:
        // Mode-neutral: bit copies, sign-bit ops, exact int->double, truncations to integer. Neither
        // flush-to-zero nor denormals-are-zero changes the result, so the FP mode isn't switched.
        print("\t{}.u64 = PPC_LOAD_U64(", f(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LFS:
        printSetFlushMode(false);
        print("\t{}.u32 = PPC_LOAD_U32(", temp());
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        println("\t{}.f64 = double({}.f32);", f(insn.operands[0]), temp());
        break;

    case PPC_INST_LFSX:
        printSetFlushMode(false);
        print("\t{}.u32 = PPC_LOAD_U32(", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        println("\t{}.f64 = double({}.f32);", f(insn.operands[0]), temp());
        break;

    case PPC_INST_LHA:
        print("\t{}.s64 = int16_t(PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}));", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LHAX:
        print("\t{}.s64 = int16_t(PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32));", r(insn.operands[2]));
        break;

    case PPC_INST_LHZ:
        print("\t{}.u64 = PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LHZX:
        print("\t{}.u64 = PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LI:
        println("\t{}.s64 = {};", r(insn.operands[0]), int32_t(insn.operands[1]));
        break;

    case PPC_INST_LIS:
        println("\t{}.s64 = {};", r(insn.operands[0]), int32_t(insn.operands[1] << 16));
        break;

    case PPC_INST_LVEBX:
    case PPC_INST_LVEHX:
    case PPC_INST_LVEWX:
    case PPC_INST_LVEWX128:
    case PPC_INST_LVX:
    case PPC_INST_LVXL:
    case PPC_INST_LVX128:
    case PPC_INST_LVXL128:
        // NOTE: for endian swapping, we reverse the whole vector instead of individual elements.
        // this is accounted for in every instruction (eg. dp3 sums yzw instead of xyz)
        print("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_shuffle_epi8(PPC_GUEST_VLOAD(base + ((", v(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32) & ~0xF)), simde_mm_load_si128((simde__m128i*)VectorMaskL)));", r(insn.operands[2]));
        break;

    case PPC_INST_LVLX:
    case PPC_INST_LVLX128:
    case PPC_INST_LVLXL:
    case PPC_INST_LVLXL128:
        print("\t{}.u32 = ", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_shuffle_epi8(PPC_GUEST_VLOAD(base + ({}.u32 & ~0xF)), simde_mm_load_si128((simde__m128i*)&VectorMaskL[({}.u32 & 0xF) * 16])));", v(insn.operands[0]), temp(), temp());
        break;

    case PPC_INST_LVRX:
    case PPC_INST_LVRX128:
    case PPC_INST_LVRXL:
    case PPC_INST_LVRXL128:
        print("\t{}.u32 = ", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, {}.u32 & 0xF ? simde_mm_shuffle_epi8(PPC_GUEST_VLOAD(base + ({}.u32 & ~0xF)), simde_mm_load_si128((simde__m128i*)&VectorMaskR[({}.u32 & 0xF) * 16])) : simde_mm_setzero_si128());", v(insn.operands[0]), temp(), temp(), temp());
        break;

    case PPC_INST_LVSL:
    case PPC_INST_LVSL128:
        print("\t{}.u32 = ", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_load_si128((simde__m128i*)&VectorShiftTableL[({}.u32 & 0xF) * 16]));", v(insn.operands[0]), temp());
        break;

    case PPC_INST_LVSR:
    case PPC_INST_LVSR128:
        print("\t{}.u32 = ", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_load_si128((simde__m128i*)&VectorShiftTableR[({}.u32 & 0xF) * 16]));", v(insn.operands[0]), temp());
        break;

    case PPC_INST_LWA:
        print("\t{}.s64 = int32_t(PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}));", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LWARX:
        print("\t{}.u32 = PPC_GUEST_LOAD(uint32_t, base + ", reserved());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        println("\t{}.u64 = __builtin_bswap32({}.u32);", r(insn.operands[0]), reserved());
        break;

    case PPC_INST_LWAX:
        print("\t{}.s64 = int32_t(PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32));", r(insn.operands[2]));
        break;

    case PPC_INST_LWBRX:
        print("\t{}.u64 = __builtin_bswap32(PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32));", r(insn.operands[2]));
        break;

    case PPC_INST_LHBRX:
        print("\t{}.u64 = __builtin_bswap16(PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32));", r(insn.operands[2]));
        break;

    case PPC_INST_LWSYNC:
        println("\tPPC_LWSYNC();");
        break;

    case PPC_INST_LWZ:
        print("\t{}.u64 = PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LWZU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U32({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_LWZX:
        print("\t{}.u64 = PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_MFCR:
        for (size_t i = 0; i < 32; i++)
        {
            constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
            println("\t{}.u64 {}= {}.{} ? 0x{:X} : 0;", r(insn.operands[0]), i == 0 ? "" : "|", cr(i / 4), fields[i % 4], 1u << (31 - i));
        }
        break;

    case PPC_INST_MFFS:
        println("\t{}.u64 = ctx.fpscr.loadFromHost();", f(insn.operands[0]));
        break;

    case PPC_INST_MFLR:
        if (!config.skipLr)
            println("\t{}.u64 = ctx.lr;", r(insn.operands[0]));
        break;

    case PPC_INST_MFMSR:
        if (!config.skipMsr)
            println("\t{}.u64 = ctx.msr;", r(insn.operands[0]));
        break;

    case PPC_INST_MFOCRF:
    {
        // FXM has one bit set, 0x80 >> n for CR field n; that field lands in its mfcr position, the rest is 0.
        const uint32_t fxm = insn.operands[1] & 0xFF;
        if (fxm == 0 || (fxm & (fxm - 1)) != 0)
        {
            println("\tPPC_UNIMPLEMENTED(0x{:X}, \"mfocrf with FXM 0x{:X}\");", base, fxm);
            problem("{:X} (in {:X}): mfocrf with FXM 0x{:X} (not a single field)", base, fn.base, fxm);
            break;
        }
        uint32_t field = 0;
        while ((0x80u >> field) != fxm)
            ++field;
        const uint32_t shift = 4 * (7 - field);
        println("\t{}.u64 = ({}.lt << {}) | ({}.gt << {}) | ({}.eq << {}) | ({}.so << {});", r(insn.operands[0]),
            cr(field), shift + 3, cr(field), shift + 2, cr(field), shift + 1, cr(field), shift);
        break;
    }

    case PPC_INST_MFTB:
        // mftb rD (TBR 268) reads the whole 64-bit timebase; the classic form can also name TBU (269).
        if (insn.operands[1] == 269)
            println("\t{}.u64 = PPC_MFTB() >> 32;", r(insn.operands[0]));
        else
            println("\t{}.u64 = PPC_MFTB();", r(insn.operands[0]));
        break;

    case PPC_INST_MFTBL:
        println("\t{}.u64 = PPC_MFTB();", r(insn.operands[0]));
        break;

    case PPC_INST_MFTBU:
        println("\t{}.u64 = PPC_MFTB() >> 32;", r(insn.operands[0]));
        break;

    case PPC_INST_MR:
        println("\t{}.u64 = {}.u64;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_MTCR:
        for (size_t i = 0; i < 32; i++)
        {
            constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
            println("\t{}.{} = ({}.u32 & 0x{:X}) != 0;", cr(i / 4), fields[i % 4], r(insn.operands[0]), 1u << (31 - i));
        }
        break;

    case PPC_INST_MTCTR:
        println("\t{}.u64 = {}.u64;", ctr(), r(insn.operands[0]));
        break;

    case PPC_INST_MTFSF:
        // FPSCR is modelled as its rounding mode only (RN, bits 30-31 = field 7, FM bit 0x01).
        // A mask without field 7 leaves RN alone; L=1 (ISA 2.05, not on Xenon) writes every field.
        if ((insn.operands[0] & 0x01) || insn.operands[2])
            println("\tctx.fpscr.storeFromGuest({}.u32);", f(insn.operands[1]));
        break;

    case PPC_INST_MTLR:
        if (!config.skipLr)
        {
            // elide_return_lr: the next instruction is blr, so this LR is only used to return,
            // which the C++ return does. Not inside an inlined helper reached by bl (its caller
            // carries on with LR as the helper set it).
            const bool beforeReturn = config.elideReturnLr && base + 4 < fn.base + fn.size &&
                ByteSwap(*(data + 1)) == 0x4E800020 && (!inliningThunk || thunkInlineTail);
            if (beforeReturn)
                println("\t// ctx.lr not stored: blr follows");
            else
                println("\tctx.lr = {}.u64;", r(insn.operands[0]));
        }
        break;

    case PPC_INST_MTMSR:
    case PPC_INST_MTMSRD:
        if (!config.skipMsr)
        {
            // Toggling MSR[EE] masks interrupts on the console; the runtime
            // turns that into a global interrupt lock (PPC_MSR_CHANGED).
            println("\t{{ const uint64_t oldMsr = ctx.msr;");
            println("\tctx.msr = ({}.u32 & 0x8020) | (ctx.msr & ~0x8020);", r(insn.operands[0]));
            println("\tPPC_MSR_CHANGED(ctx, oldMsr); }}");
        }
        break;

    case PPC_INST_MTXER:
        println("\t{}.so = ({}.u64 & 0x80000000) != 0;", xer(), r(insn.operands[0]));
        println("\t{}.ov = ({}.u64 & 0x40000000) != 0;", xer(), r(insn.operands[0]));
        println("\t{}.ca = ({}.u64 & 0x20000000) != 0;", xer(), r(insn.operands[0]));
        break;

    case PPC_INST_MULHW:
        println("\t{}.s64 = (int64_t({}.s32) * int64_t({}.s32)) >> 32;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_MULHDU:
        println("	{}.u64 = uint64_t((unsigned __int128)({}.u64) * {}.u64 >> 64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_EQV:
        println("	{}.u64 = ~({}.u64 ^ {}.u64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("	{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_MULHWU:
        println("\t{}.u64 = (uint64_t({}.u32) * uint64_t({}.u32)) >> 32;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_MULLD:
        println("\t{}.s64 = {}.s64 * {}.s64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_MULLI:
        println("\t{}.s64 = {}.s64 * {};", r(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]));
        break;

    case PPC_INST_MULLW:
        println("\t{}.s64 = int64_t({}.s32) * int64_t({}.s32);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_NAND:
        println("\t{}.u64 = ~({}.u64 & {}.u64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_NEG:
        println("\t{}.s64 = -{}.s64;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_NOP:
        // no op
        break;

    case PPC_INST_NOR:
        println("\t{}.u64 = ~({}.u64 | {}.u64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_NOT:
        println("\t{}.u64 = ~{}.u64;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_OR:
        println("\t{}.u64 = {}.u64 | {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ORC:
        println("\t{}.u64 = {}.u64 | ~{}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_ORI:
        println("\t{}.u64 = {}.u64 | {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        break;

    case PPC_INST_ORIS:
        println("\t{}.u64 = {}.u64 | {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2] << 16);
        break;

    case PPC_INST_RLDICL:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {}) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], ComputeMask(insn.operands[3], 63));
        break;

    case PPC_INST_RLDICR:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {}) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], ComputeMask(0, insn.operands[3]));
        break;

    case PPC_INST_RLDIMI:
    {
        const uint64_t mask = ComputeMask(insn.operands[3], ~insn.operands[2]);
        println("\t{}.u64 = (__builtin_rotateleft64({}.u64, {}) & 0x{:X}) | ({}.u64 & 0x{:X});", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], mask, r(insn.operands[0]), ~mask);
        break;
    }

    case PPC_INST_RLWIMI:
    {
        const uint64_t mask = ComputeMask(insn.operands[3] + 32, insn.operands[4] + 32);
        println("\t{}.u64 = (__builtin_rotateleft32({}.u32, {}) & 0x{:X}) | ({}.u64 & 0x{:X});", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], mask, r(insn.operands[0]), ~mask);
        break;
    }

    case PPC_INST_RLWINM:
        println("\t{}.u64 = __builtin_rotateleft64({}.u32 | ({}.u64 << 32), {}) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[1]), insn.operands[2], ComputeMask(insn.operands[3] + 32, insn.operands[4] + 32));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ROTLDI:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {});", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        break;

    case PPC_INST_ROTLW:
        println("\t{}.u64 = __builtin_rotateleft32({}.u32, {}.u8 & 0x1F);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_ROTLWI:
        println("\t{}.u64 = __builtin_rotateleft32({}.u32, {});", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SLD:
        println("\t{}.u64 = {}.u8 & 0x40 ? 0 : ({}.u64 << ({}.u8 & 0x7F));", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_SLW:
        println("\t{}.u64 = {}.u8 & 0x20 ? 0 : ({}.u32 << ({}.u8 & 0x3F));", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SRAD:
        println("\t{}.u64 = {}.u64 & 0x7F;", temp(), r(insn.operands[2]));
        println("\tif ({}.u64 > 0x3F) {}.u64 = 0x3F;", temp(), temp());
        println("\t{}.ca = ({}.s64 < 0) & ((({}.s64 >> {}.u64) << {}.u64) != {}.s64);", xer(), r(insn.operands[1]), r(insn.operands[1]), temp(), temp(), r(insn.operands[1]));
        println("\t{}.s64 = {}.s64 >> {}.u64;", r(insn.operands[0]), r(insn.operands[1]), temp());
        break;

    case PPC_INST_SRADI:
        if (insn.operands[2] != 0)
        {
            println("\t{}.ca = ({}.s64 < 0) & (({}.u64 & 0x{:X}) != 0);", xer(), r(insn.operands[1]), r(insn.operands[1]), ComputeMask(64 - insn.operands[2], 63));
            println("\t{}.s64 = {}.s64 >> {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        }
        else
        {
            println("\t{}.ca = 0;", xer());
            println("\t{}.s64 = {}.s64;", r(insn.operands[0]), r(insn.operands[1]));
        }
        break;

    case PPC_INST_SRAW:
        println("\t{}.u32 = {}.u32 & 0x3F;", temp(), r(insn.operands[2]));
        println("\tif ({}.u32 > 0x1F) {}.u32 = 0x1F;", temp(), temp());
        println("\t{}.ca = ({}.s32 < 0) & ((({}.s32 >> {}.u32) << {}.u32) != {}.s32);", xer(), r(insn.operands[1]), r(insn.operands[1]), temp(), temp(), r(insn.operands[1]));
        println("\t{}.s64 = {}.s32 >> {}.u32;", r(insn.operands[0]), r(insn.operands[1]), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SRAWI:
        if (insn.operands[2] != 0)
        {
            println("\t{}.ca = ({}.s32 < 0) & (({}.u32 & 0x{:X}) != 0);", xer(), r(insn.operands[1]), r(insn.operands[1]), ComputeMask(64 - insn.operands[2], 63));
            println("\t{}.s64 = {}.s32 >> {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        }
        else
        {
            println("\t{}.ca = 0;", xer());
            println("\t{}.s64 = {}.s32;", r(insn.operands[0]), r(insn.operands[1]));
        }
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SRD:
        println("\t{}.u64 = {}.u8 & 0x40 ? 0 : ({}.u64 >> ({}.u8 & 0x7F));", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_SRW:
        println("\t{}.u64 = {}.u8 & 0x20 ? 0 : ({}.u32 >> ({}.u8 & 0x3F));", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_STB:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U8(" : "\tPPC_STORE_U8(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u8);", int32_t(insn.operands[1]), r(insn.operands[0]));
        break;

    case PPC_INST_STBU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\tPPC_STORE_U8({}, {}.u8);", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_STBX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U8(" : "\tPPC_STORE_U8(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u8);", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STD:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U64(" : "\tPPC_STORE_U64(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u64);", int32_t(insn.operands[1]), r(insn.operands[0]));
        break;

    case PPC_INST_STDCX:
        println("\t{}.lt = 0;", cr(0));
        println("\t{}.gt = 0;", cr(0));
        print("\t{}.eq = __sync_bool_compare_and_swap(reinterpret_cast<uint64_t*>(base + ", cr(0));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32), {}.s64, __builtin_bswap64({}.s64));", r(insn.operands[2]), reserved(), r(insn.operands[0]));
        println("\t{}.so = {}.so;", cr(0), xer());
        break;

    case PPC_INST_STDU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\tPPC_STORE_U64({}, {}.u64);", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_STDX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U64(" : "\tPPC_STORE_U64(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u64);", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STFD:
        // Mode-neutral: bit copies, sign-bit ops, exact int->double, truncations to integer. Neither
        // flush-to-zero nor denormals-are-zero changes the result, so the FP mode isn't switched.
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U64(" : "\tPPC_STORE_U64(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u64);", int32_t(insn.operands[1]), f(insn.operands[0]));
        break;

    case PPC_INST_STFDX:
        // Mode-neutral: bit copies, sign-bit ops, exact int->double, truncations to integer. Neither
        // flush-to-zero nor denormals-are-zero changes the result, so the FP mode isn't switched.
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U64(" : "\tPPC_STORE_U64(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u64);", r(insn.operands[2]), f(insn.operands[0]));
        break;

    case PPC_INST_STFIWX:
        // Mode-neutral: bit copies, sign-bit ops, exact int->double, truncations to integer. Neither
        // flush-to-zero nor denormals-are-zero changes the result, so the FP mode isn't switched.
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u32);", r(insn.operands[2]), f(insn.operands[0]));
        break;

    case PPC_INST_STFS:
        printSetFlushMode(false);
        println("\t{}.f32 = float({}.f64);", temp(), f(insn.operands[0]));
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u32);", int32_t(insn.operands[1]), temp());
        break;

    case PPC_INST_STFSX:
        printSetFlushMode(false);
        println("\t{}.f32 = float({}.f64);", temp(), f(insn.operands[0]));
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u32);", r(insn.operands[2]), temp());
        break;

    case PPC_INST_STH:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U16(" : "\tPPC_STORE_U16(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u16);", int32_t(insn.operands[1]), r(insn.operands[0]));
        break;

    case PPC_INST_STHBRX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U16(" : "\tPPC_STORE_U16(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, __builtin_bswap16({}.u16));", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STHX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U16(" : "\tPPC_STORE_U16(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u16);", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STVEHX:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\t{} = (", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32) & ~0x1;", r(insn.operands[2]));
        println("\tPPC_STORE_U16(ea, {}.u16[7 - (({} & 0xF) >> 1)]);", v(insn.operands[0]), ea());
        break;

    case PPC_INST_STVEWX:
    case PPC_INST_STVEWX128:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\t{} = (", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32) & ~0x3;", r(insn.operands[2]));
        println("\tPPC_STORE_U32(ea, {}.u32[3 - (({} & 0xF) >> 2)]);", v(insn.operands[0]), ea());
        break;

    case PPC_INST_STVLX:
    case PPC_INST_STVLX128:
    case PPC_INST_STVLXL:
    case PPC_INST_STVLXL128:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\t{} = ", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));

        println("\tfor (size_t i = 0; i < (16 - ({} & 0xF)); i++)", ea());
        println("\t\tPPC_STORE_U8({} + i, {}.u8[15 - i]);", ea(), v(insn.operands[0]));
        break;

    case PPC_INST_STVRX:
    case PPC_INST_STVRX128:
    case PPC_INST_STVRXL:
    case PPC_INST_STVRXL128:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\t{} = ", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));

        println("\tfor (size_t i = 0; i < ({} & 0xF); i++)", ea());
        println("\t\tPPC_STORE_U8({} - i - 1, {}.u8[i]);", ea(), v(insn.operands[0]));
        break;

    case PPC_INST_STVX:
    case PPC_INST_STVXL:
    case PPC_INST_STVX128:
    case PPC_INST_STVXL128:
        print("\tPPC_GUEST_VSTORE(base + ((");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32) & ~0xF), simde_mm_shuffle_epi8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*)VectorMaskL)));", r(insn.operands[2]), v(insn.operands[0]));
        break;

    case PPC_INST_STW:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u32);", int32_t(insn.operands[1]), r(insn.operands[0]));
        break;

    case PPC_INST_STWBRX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, __builtin_bswap32({}.u32));", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STWCX:
        println("\t{}.lt = 0;", cr(0));
        println("\t{}.gt = 0;", cr(0));
        print("\t{}.eq = __sync_bool_compare_and_swap(reinterpret_cast<uint32_t*>(base + ", cr(0));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32), {}.s32, __builtin_bswap32({}.s32));", r(insn.operands[2]), reserved(), r(insn.operands[0]));
        println("\t{}.so = {}.so;", cr(0), xer());
        break;

    case PPC_INST_STWU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\tPPC_STORE_U32({}, {}.u32);", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_STWUX:
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        println("\tPPC_STORE_U32({}, {}.u32);", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        break;

    case PPC_INST_STWX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u32);", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_SUBF:
        println("\t{}.s64 = {}.s64 - {}.s64;", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SUBFC:
        println("\t{}.ca = {}.u32 >= {}.u32;", xer(), r(insn.operands[2]), r(insn.operands[1]));
        println("\t{}.s64 = {}.s64 - {}.s64;", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SUBFE:
        println("\t{}.u8 = (~{}.u32 + {}.u32 < ~{}.u32) | (~{}.u32 + {}.u32 + {}.ca < {}.ca);", temp(), r(insn.operands[1]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[1]), r(insn.operands[2]), xer(), xer());
        println("\t{}.u64 = ~{}.u64 + {}.u64 + {}.ca;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        println("\t{}.ca = {}.u8;", xer(), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SUBFIC:
        println("\t{}.ca = {}.u32 <= {};", xer(), r(insn.operands[1]), insn.operands[2]);
        println("\t{}.s64 = {} - {}.s64;", r(insn.operands[0]), int32_t(insn.operands[2]), r(insn.operands[1]));
        break;

    case PPC_INST_SYNC:
        println("\tPPC_SYNC();");
        break;

    case PPC_INST_ISYNC:
        println("\tPPC_ISYNC();");
        break;

    case PPC_INST_VADDFP:
    case PPC_INST_VADDFP128:
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_add_ps(simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDSHS:
        println("\tsimde_mm_store_si128((simde__m128i*){}.s16, simde_mm_adds_epi16(simde_mm_load_si128((simde__m128i*){}.s16), simde_mm_load_si128((simde__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUBM:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_add_epi8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUBS:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_adds_epu8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUHM:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u16, simde_mm_add_epi16(simde_mm_load_si128((simde__m128i*){}.u16), simde_mm_load_si128((simde__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUWM:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u32, simde_mm_add_epi32(simde_mm_load_si128((simde__m128i*){}.u32), simde_mm_load_si128((simde__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUWS:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u32, simde_mm_adds_epu32(simde_mm_load_si128((simde__m128i*){}.u32), simde_mm_load_si128((simde__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VAND:
    case PPC_INST_VAND128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_and_si128(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VANDC128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_andnot_si128(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VAVGSB:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_avg_epi8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VAVGSH:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_avg_epi16(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VAVGUB:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_avg_epu8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VCTSXS:
    case PPC_INST_VCFPSXWS128:
        printSetFlushMode(true);
        print("\tsimde_mm_store_si128((simde__m128i*){}.s32, simde_mm_vctsxs(", v(insn.operands[0]));
        if (insn.operands[2] != 0)
            println("simde_mm_mul_ps(simde_mm_load_ps({}.f32), simde_mm_set1_ps({}))));", v(insn.operands[1]), 1u << insn.operands[2]);
        else
            println("simde_mm_load_ps({}.f32)));", v(insn.operands[1]));
        break;

    case PPC_INST_VCFSX:
    case PPC_INST_VCSXWFP128:
    {
        printSetFlushMode(true);
        print("\tsimde_mm_store_ps({}.f32, ", v(insn.operands[0]));
        if (insn.operands[2] != 0)
        {
            const float value = ldexp(1.0f, -int32_t(insn.operands[2]));
            println("simde_mm_mul_ps(simde_mm_cvtepi32_ps(simde_mm_load_si128((simde__m128i*){}.u32)), simde_mm_castsi128_ps(simde_mm_set1_epi32(int(0x{:X})))));", v(insn.operands[1]), *reinterpret_cast<const uint32_t*>(&value));
        }
        else
        {
            println("simde_mm_cvtepi32_ps(simde_mm_load_si128((simde__m128i*){}.u32)));", v(insn.operands[1]));
        }
        break;
    }

    case PPC_INST_VCFUX:
    case PPC_INST_VCUXWFP128:
    {
        printSetFlushMode(true);
        print("\tsimde_mm_store_ps({}.f32, ", v(insn.operands[0]));
        if (insn.operands[2] != 0)
        {
            const float value = ldexp(1.0f, -int32_t(insn.operands[2]));
            println("simde_mm_mul_ps(simde_mm_cvtepu32_ps_(simde_mm_load_si128((simde__m128i*){}.u32)), simde_mm_castsi128_ps(simde_mm_set1_epi32(int(0x{:X})))));", v(insn.operands[1]), *reinterpret_cast<const uint32_t*>(&value));
        }
        else
        {
            println("simde_mm_cvtepu32_ps_(simde_mm_load_si128((simde__m128i*){}.u32)));", v(insn.operands[1]));
        }
        break;
    }

    case PPC_INST_VCMPBFP:
    case PPC_INST_VCMPBFP128:
        // Bounds compare, per lane: bit 31 set unless a <= b, bit 30 set unless a >= -b (both for NaN).
        // The record form sets CR6's EQ when every lane is in bounds (all results zero).
        printSetFlushMode(true);
        println("\t{{ simde__m128 a = simde_mm_load_ps({}.f32), b = simde_mm_load_ps({}.f32);", v(insn.operands[1]), v(insn.operands[2]));
        println("\tsimde__m128i le = simde_mm_castps_si128(simde_mm_cmple_ps(a, b)), ge = simde_mm_castps_si128(simde_mm_cmpge_ps(a, simde_mm_xor_ps(b, simde_mm_set1_ps(-0.0f))));");
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_or_si128(simde_mm_andnot_si128(le, simde_mm_set1_epi32(int(0x80000000))), simde_mm_andnot_si128(ge, simde_mm_set1_epi32(0x40000000)))); }}", v(insn.operands[0]));
        if (strchr(insn.opcode->name, '.'))
        {
            println("\t{}.lt = 0; {}.gt = 0; {}.so = 0;", cr(6), cr(6), cr(6));
            println("\t{}.eq = simde_mm_movemask_epi8(simde_mm_cmpeq_epi32(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_setzero_si128())) == 0xFFFF;", cr(6), v(insn.operands[0]));
        }
        break;

    case PPC_INST_VCMPEQFP:
    case PPC_INST_VCMPEQFP128:
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_cmpeq_ps(simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(simde_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPEQUB:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_cmpeq_epi8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(simde_mm_load_si128((simde__m128i*){}.u8), 0xFFFF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPEQUW:
    case PPC_INST_VCMPEQUW128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_cmpeq_epi32(simde_mm_load_si128((simde__m128i*){}.u32), simde_mm_load_si128((simde__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(simde_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGTUW:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_cmpgt_epi32(simde_mm_xor_si128(simde_mm_load_si128((simde__m128i*){}.u32), simde_mm_set1_epi32(int(0x80000000))), simde_mm_xor_si128(simde_mm_load_si128((simde__m128i*){}.u32), simde_mm_set1_epi32(int(0x80000000)))));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(simde_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGEFP:
    case PPC_INST_VCMPGEFP128:
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_cmpge_ps(simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(simde_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGTFP:
    case PPC_INST_VCMPGTFP128:
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_cmpgt_ps(simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(simde_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGTUB:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_cmpgt_epu8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VCMPGTUH:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_cmpgt_epu16(simde_mm_load_si128((simde__m128i*){}.u16), simde_mm_load_si128((simde__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VEXPTEFP:
    case PPC_INST_VEXPTEFP128:
        // TODO: vectorize
        printSetFlushMode(true);
        for (size_t i = 0; i < 4; i++)
            println("\t{}.f32[{}] = exp2f({}.f32[{}]);", v(insn.operands[0]), i, v(insn.operands[1]), i);
        break;

    case PPC_INST_VLOGEFP:
    case PPC_INST_VLOGEFP128:
        // TODO: vectorize
        printSetFlushMode(true);
        for (size_t i = 0; i < 4; i++)
            println("\t{}.f32[{}] = log2f(({}.u32[{}] & 0x7F800000) == 0 ? 0.0f : {}.f32[{}]);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[1]), i);
        break;

    case PPC_INST_VMADDCFP128:
    case PPC_INST_VMADDFP:
    case PPC_INST_VMADDFP128:
        printSetFlushMode(true);
        if (config.fusedMadd)
        {
            println("\tsimde_mm_store_ps({}.f32, simde_mm_fmadd_ps(simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), v(insn.operands[3]));
            break;
        }
        println("\tsimde_mm_store_ps({}.f32, simde_mm_add_ps(simde_mm_mul_ps(simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32)), simde_mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), v(insn.operands[3]));
        break;

    case PPC_INST_VMAXFP:
    case PPC_INST_VMAXFP128:
        printSetFlushMode(true);
        // x86 returns the second operand for a NaN or for equal zeros. Both orders combined give the
        // right zero sign; a NaN input gives that NaN quieted (vA's if both are NaN).
        println("\t{{ simde__m128 a = simde_mm_load_ps({}.f32), b = simde_mm_load_ps({}.f32);", v(insn.operands[1]), v(insn.operands[2]));
        println("\tsimde__m128 m = simde_mm_and_ps(simde_mm_max_ps(a, b), simde_mm_max_ps(b, a));");
        println("\tsimde__m128 q = simde_mm_or_ps(simde_mm_blendv_ps(b, a, simde_mm_cmpunord_ps(a, a)), simde_mm_castsi128_ps(simde_mm_set1_epi32(0x00400000)));");
        println("\tsimde_mm_store_ps({}.f32, simde_mm_blendv_ps(m, q, simde_mm_cmpunord_ps(a, b))); }}", v(insn.operands[0]));
        break;

    case PPC_INST_VMAXSW:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u32, simde_mm_max_epi32(simde_mm_load_si128((simde__m128i*){}.u32), simde_mm_load_si128((simde__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMINFP:
    case PPC_INST_VMINFP128:
        printSetFlushMode(true);
        // x86 returns the second operand for a NaN or for equal zeros. Both orders combined give the
        // right zero sign; a NaN input gives that NaN quieted (vA's if both are NaN).
        println("\t{{ simde__m128 a = simde_mm_load_ps({}.f32), b = simde_mm_load_ps({}.f32);", v(insn.operands[1]), v(insn.operands[2]));
        println("\tsimde__m128 m = simde_mm_or_ps(simde_mm_min_ps(a, b), simde_mm_min_ps(b, a));");
        println("\tsimde__m128 q = simde_mm_or_ps(simde_mm_blendv_ps(b, a, simde_mm_cmpunord_ps(a, a)), simde_mm_castsi128_ps(simde_mm_set1_epi32(0x00400000)));");
        println("\tsimde_mm_store_ps({}.f32, simde_mm_blendv_ps(m, q, simde_mm_cmpunord_ps(a, b))); }}", v(insn.operands[0]));
        break;

    case PPC_INST_VMRGHB:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_unpackhi_epi8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGHH:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u16, simde_mm_unpackhi_epi16(simde_mm_load_si128((simde__m128i*){}.u16), simde_mm_load_si128((simde__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGHW:
    case PPC_INST_VMRGHW128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u32, simde_mm_unpackhi_epi32(simde_mm_load_si128((simde__m128i*){}.u32), simde_mm_load_si128((simde__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGLB:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_unpacklo_epi8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGLH:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u16, simde_mm_unpacklo_epi16(simde_mm_load_si128((simde__m128i*){}.u16), simde_mm_load_si128((simde__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGLW:
    case PPC_INST_VMRGLW128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u32, simde_mm_unpacklo_epi32(simde_mm_load_si128((simde__m128i*){}.u32), simde_mm_load_si128((simde__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMSUM3FP128:
        // NOTE: accounting for full vector reversal here. should dot product yzw instead of xyz
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_dp_ps(simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32), 0xEF));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMSUM4FP128:
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_dp_ps(simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32), 0xFF));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMULFP128:
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_mul_ps(simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VNMSUBFP:
    case PPC_INST_VNMSUBFP128:
        printSetFlushMode(true);
        if (config.fusedMadd)
        {
            // -(a*c - b), negated after the fused op so the zero sign matches.
            println("\tsimde_mm_store_ps({}.f32, simde_mm_xor_ps(simde_mm_fmsub_ps(simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32)), simde_mm_castsi128_ps(simde_mm_set1_epi32(int(0x80000000)))));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), v(insn.operands[3]));
            break;
        }
        println("\tsimde_mm_store_ps({}.f32, simde_mm_xor_ps(simde_mm_sub_ps(simde_mm_mul_ps(simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32)), simde_mm_load_ps({}.f32)), simde_mm_castsi128_ps(simde_mm_set1_epi32(int(0x80000000)))));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), v(insn.operands[3]));
        break;

    case PPC_INST_VNOR:
    case PPC_INST_VNOR128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_xor_si128(simde_mm_or_si128(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)), simde_mm_set1_epi32(-1)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VOR:
    case PPC_INST_VOR128:
        print("\tsimde_mm_store_si128((simde__m128i*){}.u8, ", v(insn.operands[0]));

        if (insn.operands[1] != insn.operands[2])
            println("simde_mm_or_si128(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[1]), v(insn.operands[2]));
        else
            println("simde_mm_load_si128((simde__m128i*){}.u8));", v(insn.operands[1]));

        break;

    case PPC_INST_VPERM:
    case PPC_INST_VPERM128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_perm_epi8_(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), v(insn.operands[3]));
        break;

    case PPC_INST_VPERMWI128:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t x = 3 - (insn.operands[2] & 0x3);
        uint32_t y = 3 - ((insn.operands[2] >> 2) & 0x3);
        uint32_t z = 3 - ((insn.operands[2] >> 4) & 0x3);
        uint32_t w = 3 - ((insn.operands[2] >> 6) & 0x3);
        uint32_t perm = x | (y << 2) | (z << 4) | (w << 6);
        println("\tsimde_mm_store_si128((simde__m128i*){}.u32, simde_mm_shuffle_epi32(simde_mm_load_si128((simde__m128i*){}.u32), 0x{:X}));", v(insn.operands[0]), v(insn.operands[1]), perm);
        break;
    }

    case PPC_INST_VPKD3D128:
        // TODO: vectorize somehow?
        // NOTE: handling vector reversal here too
        printSetFlushMode(true);
        // Only D3DCOLOR keeps its old dedicated code (it stages through temps, so vD == vB is safe).
        // The old FLOAT16_2/FLOAT16_4 code wrote vD while still reading vB, which broke
        // `vpkd3d128 v0,v0,5,2,2` (FM2 has 8) and type 3 with shift 2; they take the generic path.
        if (!(insn.operands[2] == 0 && insn.operands[3] == 1))
        {
            // Generic form, after Xenia: pack vB into P (big-endian elements x,y,z,w), then each
            // element of vD keeps its old value or takes one of P's, by (pack, shift).
            const uint32_t type = insn.operands[2], pack = insn.operands[3], shift = insn.operands[4];
            struct Select { uint8_t fromP, index; };
            static constexpr Select pack1[4][4] = {
                { {0,0}, {0,1}, {0,2}, {1,3} }, { {0,0}, {0,1}, {1,3}, {0,3} },
                { {0,0}, {1,3}, {0,2}, {0,3} }, { {1,3}, {0,1}, {0,2}, {0,3} } };
            static constexpr Select pack2[4][4] = {
                { {0,0}, {0,1}, {1,2}, {1,3} }, { {0,0}, {1,2}, {1,3}, {0,3} },
                { {1,2}, {1,3}, {0,2}, {0,3} }, { {1,3}, {0,1}, {0,2}, {0,3} } };
            static constexpr Select pack3[4][4] = {
                { {0,0}, {0,1}, {1,2}, {1,3} }, { {0,0}, {1,2}, {1,3}, {0,3} },
                { {1,2}, {1,3}, {0,2}, {0,3} }, { {0,0}, {0,1}, {0,2}, {1,2} } };
            const Select* selects = pack == 1 ? pack1[shift] : pack == 2 ? pack2[shift] : pack == 3 ? pack3[shift] : nullptr;
            if (selects == nullptr || shift > 3 || type > 5)
            {
                println("\tPPC_UNIMPLEMENTED(0x{:X}, \"{} type {} pack {}\");", base, insn.opcode->name, type, pack);
                problem("{:X} (in {:X}): {} type {} pack {} isn't implemented", base, fn.base, insn.opcode->name, type, pack);
                break;
            }

            const auto b = v(insn.operands[1]);
            auto element = [&](int k) { return fmt::format("{}.f32[{}]", b, 3 - k); }; // big-endian element k
            auto clamp = [&](int k, uint32_t lo, uint32_t hi, uint32_t mask) { return fmt::format("(ppc_pack_clamp({}, 0x{:X}, 0x{:X}) & 0x{:X})", element(k), lo, hi, mask); };
            auto half = [&](int k) { return fmt::format("uint32_t(ppc_float_to_xenos_half({}))", element(k)); };
            std::string P[4] = { "0", "0", "0", "0" };
            switch (type)
            {
            case 0: // D3DCOLOR: ARGB in w
                P[3] = fmt::format("{} << 24 | {} << 16 | {} << 8 | {}", clamp(3, 0x40400000, 0x404000FF, 0xFF), clamp(0, 0x40400000, 0x404000FF, 0xFF), clamp(1, 0x40400000, 0x404000FF, 0xFF), clamp(2, 0x40400000, 0x404000FF, 0xFF));
                break;
            case 1: // NORMSHORT2: x:y in w
                P[3] = fmt::format("{} << 16 | {}", clamp(0, 0x403F8001, 0x40407FFF, 0xFFFF), clamp(1, 0x403F8001, 0x40407FFF, 0xFFFF));
                break;
            case 2: // NORMPACKED32 2:10:10:10 (w:z:y:x), in every element
            {
                const auto packed = fmt::format("({} | {} << 10 | {} << 20 | {} << 30)", clamp(0, 0x403FFE01, 0x404001FF, 0x3FF), clamp(1, 0x403FFE01, 0x404001FF, 0x3FF), clamp(2, 0x403FFE01, 0x404001FF, 0x3FF), clamp(3, 0x40400000, 0x40400003, 0x3));
                println("\t{}.u32 = {};", temp(), packed);
                P[0] = P[1] = P[2] = P[3] = fmt::format("{}.u32", temp());
                break;
            }
            case 3: // FLOAT16_2: x:y in w
                P[3] = fmt::format("{} << 16 | {}", half(0), half(1));
                break;
            case 4: // NORMSHORT4: x:y in z, z:w in w
                P[2] = fmt::format("{} << 16 | {}", clamp(0, 0x403F8001, 0x40407FFF, 0xFFFF), clamp(1, 0x403F8001, 0x40407FFF, 0xFFFF));
                P[3] = fmt::format("{} << 16 | {}", clamp(2, 0x403F8001, 0x40407FFF, 0xFFFF), clamp(3, 0x403F8001, 0x40407FFF, 0xFFFF));
                break;
            case 5: // FLOAT16_4: x:y in z, z:w in w
                P[2] = fmt::format("{} << 16 | {}", half(0), half(1));
                P[3] = fmt::format("{} << 16 | {}", half(2), half(3));
                break;
            }

            // P is built from vB before vD is written (they may be the same register).
            for (int k = 0; k < 4; k++)
            {
                if (selects[k].fromP)
                    println("\t{}.u32[{}] = {};", vTemp(), 3 - k, P[selects[k].index]);
            }
            for (int k = 0; k < 4; k++)
            {
                if (selects[k].fromP)
                    println("\t{}.u32[{}] = {}.u32[{}];", v(insn.operands[0]), 3 - k, vTemp(), 3 - k);
                else if (selects[k].index != k)
                    println("\t{}.u32[{}] = {}.u32[{}];", v(insn.operands[0]), 3 - k, v(insn.operands[0]), 3 - selects[k].index);
            }
            break;
        }

        switch (insn.operands[2])
        {
        case 0: // D3D color
            if (insn.operands[3] != 1)
                fmt::println("Unexpected D3D color pack instruction at {:X}", base);

            for (size_t i = 0; i < 4; i++)
            {
                constexpr size_t indices[] = { 3, 0, 1, 2 };
                println("\t{}.u32[{}] = 0x404000FF;", vTemp(), i);
                println("\t{}.f32[{}] = !({}.f32[{}] > 3.0f) ? 3.0f : ({}.f32[{}] > {}.f32[{}] ? {}.f32[{}] : {}.f32[{}]);", vTemp(), i, v(insn.operands[1]), i, v(insn.operands[1]), i, vTemp(), i, vTemp(), i, v(insn.operands[1]), i);
                println("\t{}.u32 {}= uint32_t({}.u8[{}]) << {};", temp(), i == 0 ? "" : "|", vTemp(), i * 4, indices[i] * 8);
            }
            println("\t{}.u32[{}] = {}.u32;", v(insn.operands[0]), insn.operands[4], temp());
            break;

        default:
            println("\tPPC_UNIMPLEMENTED(0x{:X}, \"{} type {}\");", base, insn.opcode->name, insn.operands[2]);
            problem("{:X} (in {:X}): {} type {} isn't implemented", base, fn.base, insn.opcode->name, insn.operands[2]);
            break;
        }
        break;

    case PPC_INST_VPKSHUS:
    case PPC_INST_VPKSHUS128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_packus_epi16(simde_mm_load_si128((simde__m128i*){}.s16), simde_mm_load_si128((simde__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VREFP:
    case PPC_INST_VREFP128:
        // TODO: see if we can use rcp safely
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_div_ps(simde_mm_set1_ps(1), simde_mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRFIM:
    case PPC_INST_VRFIM128:
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_round_ps(simde_mm_load_ps({}.f32), SIMDE_MM_FROUND_TO_NEG_INF | SIMDE_MM_FROUND_NO_EXC));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRFIN:
    case PPC_INST_VRFIN128:
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_round_ps(simde_mm_load_ps({}.f32), SIMDE_MM_FROUND_TO_NEAREST_INT | SIMDE_MM_FROUND_NO_EXC));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRFIZ:
    case PPC_INST_VRFIZ128:
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_round_ps(simde_mm_load_ps({}.f32), SIMDE_MM_FROUND_TO_ZERO | SIMDE_MM_FROUND_NO_EXC));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRLIMI128:
    {
        constexpr size_t shuffles[] = { SIMDE_MM_SHUFFLE(3, 2, 1, 0), SIMDE_MM_SHUFFLE(2, 1, 0, 3), SIMDE_MM_SHUFFLE(1, 0, 3, 2), SIMDE_MM_SHUFFLE(0, 3, 2, 1) };
        println("\tsimde_mm_store_ps({}.f32, simde_mm_blend_ps(simde_mm_load_ps({}.f32), simde_mm_permute_ps(simde_mm_load_ps({}.f32), {}), {}));", v(insn.operands[0]), v(insn.operands[0]), v(insn.operands[1]), shuffles[insn.operands[3]], insn.operands[2]);
        break;
    }

    case PPC_INST_VRSQRTEFP:
    case PPC_INST_VRSQRTEFP128:
        if (config.exactEstimates)
        {
            // Integer table lookup per element; vD may be vB, so each element reads before it writes.
            for (size_t i = 0; i < 4; i++)
                println("\t{}.u32[{}] = ppc_vrsqrtefp({}.u32[{}]);", v(insn.operands[0]), i, v(insn.operands[1]), i);
            break;
        }
        // TODO: see if we can use rsqrt safely
        // TODO: we can detect if the input is from a dot product and apply logic only on one value
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_div_ps(simde_mm_set1_ps(1), simde_mm_sqrt_ps(simde_mm_load_ps({}.f32))));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VSEL:
    case PPC_INST_VSEL128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_or_si128(simde_mm_andnot_si128(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)), simde_mm_and_si128(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8))));", v(insn.operands[0]), v(insn.operands[3]), v(insn.operands[1]), v(insn.operands[3]), v(insn.operands[2]));
        break;

    case PPC_INST_VSLB:
        // TODO: vectorize
        for (size_t i = 0; i < 16; i++)
            println("\t{}.u8[{}] = {}.u8[{}] << ({}.u8[{}] & 0x7);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i);
        break;

    case PPC_INST_VSLDOI:
    case PPC_INST_VSLDOI128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_alignr_epi8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8), {}));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), 16 - insn.operands[3]);
        break;

    case PPC_INST_VSLW:
    case PPC_INST_VSLW128:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 4; i++)
            println("\t{}.u32[{}] = {}.u32[{}] << ({}.u8[{}] & 0x1F);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i * 4);
        break;

    case PPC_INST_VSPLTB:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t perm = 15 - insn.operands[2];
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_shuffle_epi8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_set1_epi8(char(0x{:X}))));", v(insn.operands[0]), v(insn.operands[1]), perm);
        break;
    }

    case PPC_INST_VSPLTH:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t perm = 7 - insn.operands[2];
        perm = (perm * 2) | ((perm * 2 + 1) << 8);
        println("\tsimde_mm_store_si128((simde__m128i*){}.u16, simde_mm_shuffle_epi8(simde_mm_load_si128((simde__m128i*){}.u16), simde_mm_set1_epi16(short(0x{:X}))));", v(insn.operands[0]), v(insn.operands[1]), perm);
        break;
    }

    case PPC_INST_VSPLTISB:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_set1_epi8(char(0x{:X})));", v(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_VSPLTISW:
    case PPC_INST_VSPLTISW128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u32, simde_mm_set1_epi32(int(0x{:X})));", v(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_VSPLTW:
    case PPC_INST_VSPLTW128:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t perm = 3 - insn.operands[2];
        perm |= (perm << 2) | (perm << 4) | (perm << 6);
        println("\tsimde_mm_store_si128((simde__m128i*){}.u32, simde_mm_shuffle_epi32(simde_mm_load_si128((simde__m128i*){}.u32), 0x{:X}));", v(insn.operands[0]), v(insn.operands[1]), perm);
        break;
    }

    case PPC_INST_VADDSWS:
        for (size_t i = 0; i < 4; i++)
        {
            println("	{}.s64 = int64_t({}.s32[{}]) + int64_t({}.s32[{}]);", temp(), v(insn.operands[1]), i, v(insn.operands[2]), i);
            println("	{}.s32[{}] = {}.s64 > INT_MAX ? INT_MAX : {}.s64 < INT_MIN ? INT_MIN : {}.s64;", v(insn.operands[0]), i, temp(), temp(), temp());
        }
        break;

    case PPC_INST_VADDSBS:
        println("	simde_mm_store_si128((simde__m128i*){}.u8, simde_mm_adds_epi8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSUBUWM:
        println("	simde_mm_store_si128((simde__m128i*){}.u32, simde_mm_sub_epi32(simde_mm_load_si128((simde__m128i*){}.u32), simde_mm_load_si128((simde__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VANDC:
        println("	simde_mm_store_si128((simde__m128i*){}.u8, simde_mm_andnot_si128(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VSRB:
        for (size_t i = 0; i < 16; i++)
            println("	{}.u8[{}] = {}.u8[{}] >> ({}.u8[{}] & 0x7);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i);
        break;

    case PPC_INST_VPKSWSS:
    case PPC_INST_VPKSWSS128:
        println("	simde_mm_store_si128((simde__m128i*){}.s16, simde_mm_packs_epi32(simde_mm_load_si128((simde__m128i*){}.s32), simde_mm_load_si128((simde__m128i*){}.s32)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VCTUXS:
    case PPC_INST_VCFPUXWS128:
        printSetFlushMode(true);
        for (size_t i = 0; i < 4; i++)
        {
            println("	{}.f64 = double({}.f32[{}]) * {}.0;", temp(), v(insn.operands[1]), i, 1u << insn.operands[2]);
            println("	{}.u32[{}] = !({}.f64 > 0.0) ? 0u : {}.f64 >= 4294967295.0 ? 0xFFFFFFFFu : uint32_t({}.f64);", vTemp(), i, temp(), temp(), temp());
        }
        println("	{} = {};", v(insn.operands[0]), vTemp());
        break;

    case PPC_INST_VSL:
    case PPC_INST_VSLO:
    case PPC_INST_VSLO128:
    case PPC_INST_VSRO:
    case PPC_INST_VSRO128:
    {
        const bool left = insn.opcode->id != PPC_INST_VSRO && insn.opcode->id != PPC_INST_VSRO128;
        const char* count = insn.opcode->id == PPC_INST_VSL ? "& 0x7" : "& 0x78";
        println("	{{ unsigned __int128 x; __builtin_memcpy(&x, {}.u8, 16); x {}= ({}.u8[0] {}); __builtin_memcpy({}.u8, &x, 16); }}",
            v(insn.operands[1]), left ? "<<" : ">>", v(insn.operands[2]), count, v(insn.operands[0]));
        break;
    }

    case PPC_INST_VSR:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_vsr(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSRAW:
    case PPC_INST_VSRAW128:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 4; i++)
            println("\t{}.s32[{}] = {}.s32[{}] >> ({}.u8[{}] & 0x1F);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i * 4);
        break;

    case PPC_INST_VSRW:
    case PPC_INST_VSRW128:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 4; i++)
            println("\t{}.u32[{}] = {}.u32[{}] >> ({}.u8[{}] & 0x1F);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i * 4);
        break;

    case PPC_INST_VSUBFP:
    case PPC_INST_VSUBFP128:
        printSetFlushMode(true);
        println("\tsimde_mm_store_ps({}.f32, simde_mm_sub_ps(simde_mm_load_ps({}.f32), simde_mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSUBSWS:
        // TODO: vectorize
        for (size_t i = 0; i < 4; i++)
        {
            println("\t{}.s64 = int64_t({}.s32[{}]) - int64_t({}.s32[{}]);", temp(), v(insn.operands[1]), i, v(insn.operands[2]), i);
            println("\t{}.s32[{}] = {}.s64 > INT_MAX ? INT_MAX : {}.s64 < INT_MIN ? INT_MIN : {}.s64;", v(insn.operands[0]), i, temp(), temp(), temp());
        }
        break;

    case PPC_INST_VSUBUBS:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_subs_epu8(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSUBUHM:
        println("\tsimde_mm_store_si128((simde__m128i*){}.u8, simde_mm_sub_epi16(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VUPKD3D128:
        // TODO: vectorize somehow?
        // NOTE: handling vector reversal here too
        switch (insn.operands[2] >> 2)
        {
        case 0: // D3D color
            for (size_t i = 0; i < 4; i++)
            {
                constexpr size_t indices[] = { 3, 0, 1, 2 };
                println("\t{}.u32[{}] = {}.u8[{}] | 0x3F800000;", vTemp(), i, v(insn.operands[1]), indices[i]);
            }
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        case 1: // 2 shorts
            for (size_t i = 0; i < 2; i++)
            {
                println("\t{}.f32 = 3.0f;", temp());
                println("\t{}.s32 += {}.s16[{}];", temp(), v(insn.operands[1]), 1 - i);
                println("\t{}.f32[{}] = {}.f32;", vTemp(), 3 - i, temp());
            }
            println("\t{}.f32[1] = 0.0f;", vTemp());
            println("\t{}.f32[0] = 1.0f;", vTemp());
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        case 2: // 2_10_10_10 (guest last word: x bits 0-9, y 10-19, z 20-29 signed; w 30-31 unsigned)
            for (size_t i = 0; i < 3; i++)
            {
                println("\t{}.f32 = 3.0f;", temp());
                println("\t{}.s32 += int32_t({}.u32[0] << {}) >> 22;", temp(), v(insn.operands[1]), 22 - 10 * i);
                println("\t{}.f32[{}] = {}.f32;", vTemp(), 3 - i, temp());
            }
            println("\t{}.f32 = 1.0f;", temp());
            println("\t{}.s32 += {}.u32[0] >> 30;", temp(), v(insn.operands[1]));
            println("\t{}.f32[0] = {}.f32;", vTemp(), temp());
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        case 4: // 4 shorts (guest x,y,z,w in the last two words)
            for (size_t i = 0; i < 4; i++)
            {
                println("\t{}.f32 = 3.0f;", temp());
                println("\t{}.s32 += {}.s16[{}];", temp(), v(insn.operands[1]), 3 - i);
                println("\t{}.f32[{}] = {}.f32;", vTemp(), 3 - i, temp());
            }
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        case 6: // 4_20_20_20 (guest last two words, as one 64-bit value: x bits 0-19, y 20-39, z 40-59 signed; w 60-63 unsigned)
            for (size_t i = 0; i < 3; i++)
            {
                println("\t{}.f32 = 3.0f;", temp());
                println("\t{}.s32 += int32_t(int64_t({}.u64[0] << {}) >> 44);", temp(), v(insn.operands[1]), 44 - 20 * i);
                println("\t{}.f32[{}] = {}.f32;", vTemp(), 3 - i, temp());
            }
            println("\t{}.f32 = 1.0f;", temp());
            println("\t{}.s32 += int32_t({}.u64[0] >> 60);", temp(), v(insn.operands[1]));
            println("\t{}.f32[0] = {}.f32;", vTemp(), temp());
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        case 3: // 2 halfs (guest x,y in the last word), z = 0, w = 1
            println("\t{}.f32[3] = ppc_half_to_float({}.u16[1]);", vTemp(), v(insn.operands[1]));
            println("\t{}.f32[2] = ppc_half_to_float({}.u16[0]);", vTemp(), v(insn.operands[1]));
            println("\t{}.f32[1] = 0.0f;", vTemp());
            println("\t{}.f32[0] = 1.0f;", vTemp());
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        case 5: // 4 halfs (guest x,y,z,w in the last two words)
            for (size_t i = 0; i < 4; i++)
                println("\t{}.f32[{}] = ppc_half_to_float({}.u16[{}]);", vTemp(), 3 - i, v(insn.operands[1]), 3 - i);
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        default:
            println("\tPPC_UNIMPLEMENTED(0x{:X}, \"{} type {}\");", base, insn.opcode->name, insn.operands[2] >> 2);
            problem("{:X} (in {:X}): {} type {} isn't implemented", base, fn.base, insn.opcode->name, insn.operands[2] >> 2);
            break;
        }
        break;

    case PPC_INST_VUPKHSB:
    case PPC_INST_VUPKHSB128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.s16, simde_mm_cvtepi8_epi16(simde_mm_unpackhi_epi64(simde_mm_load_si128((simde__m128i*){}.s8), simde_mm_load_si128((simde__m128i*){}.s8))));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        break;

    case PPC_INST_VUPKHSH:
    case PPC_INST_VUPKHSH128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.s32, simde_mm_cvtepi16_epi32(simde_mm_unpackhi_epi64(simde_mm_load_si128((simde__m128i*){}.s16), simde_mm_load_si128((simde__m128i*){}.s16))));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        break;

    case PPC_INST_VUPKLSB:
    case PPC_INST_VUPKLSB128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.s32, simde_mm_cvtepi8_epi16(simde_mm_load_si128((simde__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VUPKLSH:
    case PPC_INST_VUPKLSH128:
        println("\tsimde_mm_store_si128((simde__m128i*){}.s32, simde_mm_cvtepi16_epi32(simde_mm_load_si128((simde__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VXOR:
    case PPC_INST_VXOR128:
        print("\tsimde_mm_store_si128((simde__m128i*){}.u8, ", v(insn.operands[0]));

        if (insn.operands[1] != insn.operands[2])
            println("simde_mm_xor_si128(simde_mm_load_si128((simde__m128i*){}.u8), simde_mm_load_si128((simde__m128i*){}.u8)));", v(insn.operands[1]), v(insn.operands[2]));
        else
            println("simde_mm_setzero_si128());");

        break;

    case PPC_INST_XOR:
        println("\t{}.u64 = {}.u64 ^ {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_XORI:
        println("\t{}.u64 = {}.u64 ^ {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        break;

    case PPC_INST_XORIS:
        println("\t{}.u64 = {}.u64 ^ {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2] << 16);
        break;

    default:
        // Branch and trap aliases are decoded from their fields.
        if (printGenericBranch() || printGenericTrap())
            break;
        return false;
    }

    // Record forms (name ends in '.'). An integer op sets cr0 from its 32-bit result; cases that
    // don't do it themselves get it here. Floating-point ones set cr1 from FPSCR[FX,FEX,VX,OX],
    // which isn't modelled: no exception bits are ever set, so cr1 is cleared. Vector compares set cr6.
    if (strchr(insn.opcode->name, '.') && out.find("cr0", outStart) == std::string::npos &&
        out.find("cr1", outStart) == std::string::npos && out.find("cr6", outStart) == std::string::npos)
    {
        const uint32_t primary = insn.instruction >> 26;
        if (primary == 59 || primary == 63)
        {
            println("\t{}.lt = 0;", cr(1));
            println("\t{}.gt = 0;", cr(1));
            println("\t{}.eq = 0;", cr(1));
            println("\t{}.so = 0;", cr(1));
        }
        else if (primary != 4)
        {
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        }
        else
        {
            // Vector compare: every element of vD is all ones or all zeros.
            println("\t{}.setFromMask(simde_mm_load_si128((simde__m128i*){}.u8), 0xFFFF);", cr(6), v(insn.operands[0]));
        }
    }

    if (midAsmHook != config.midAsmHooks.end() && midAsmHook->second.afterInstruction)
        printMidAsmHook();
    
    return true;
}

// A bctr whose target was loaded from a table of code addresses inside this function: within the
// few instructions before it, lis + addi (the table address) and the mtctr, and the table's first
// word points into the function. (A table of function pointers is a tail call, not a switch.) Also
// the two padding words the original check knew about. Catches switch tables that neither the file
// nor the patterns cover.
static bool LooksLikeJumpTable(const Image& image, const Function& fn, const uint32_t* data, size_t base)
{
    const uint32_t prev = *(data - 1);
    if (prev == 0x07008038 || prev == 0x00000060)
        return true;

    bool mtctr = false;
    int64_t hi = -1, lo = 0;
    uint32_t tableReg = 0;
    const size_t count = std::min<size_t>(8, (base - fn.base) / 4);
    for (size_t i = count; i >= 1; i--)
    {
        const uint32_t word = ByteSwap(*(data - i));
        const uint32_t rd = (word >> 21) & 0x1F, ra = (word >> 16) & 0x1F;
        if ((word >> 26) == 15 && ra == 0) { hi = int64_t(int32_t(word << 16)); lo = 0; tableReg = rd; } // lis
        else if ((word >> 26) == 14 && hi != -1 && ra == tableReg && rd == tableReg) lo = int16_t(word & 0xFFFF); // addi
        if ((word & 0xFC1FFFFF) == 0x7C0903A6) mtctr = true; // mtspr ctr,rS
    }
    if (!mtctr || hi == -1)
        return false;

    const uint32_t table = uint32_t(hi + lo);
    for (const auto& section : image.sections)
    {
        if (section.data != nullptr && table >= section.base && table + 4 <= section.base + section.size)
        {
            const uint32_t first = ByteSwap(*(const uint32_t*)(section.data + (table - section.base)));
            return first >= fn.base && first < fn.base + fn.size;
        }
    }
    return false;
}

extern "C" const powerpc_opcode powerpc_opcodes[];
extern "C" const int powerpc_num_opcodes;

// Primary opcode 4 with bit 4 set is always vsldoi128 on Xenon (no AltiVec or other VMX128 form sets it), but the
// disassembler's table lists the PPC405/440 multiply and multiply-accumulate entries (mullhwu., mulhhwu, macchw...)
// first, and some vsldoi128 encodings match them. Forza Motorsport 3 has one at 8284AA90, decoded as mullhwu.
// (really vsldoi128 v11,v0,v61,12). Xenon has no PPC405 instructions, so re-decode any such match as vsldoi128.
static void DecodeVsldoi128(ppc_insn& insn)
{
    static const powerpc_opcode* vsldoi128 = []
        {
            for (int i = 0; i < powerpc_num_opcodes; i++)
            {
                if (powerpc_opcodes[i].id == PPC_INST_VSLDOI128)
                    return &powerpc_opcodes[i];
            }
            return (const powerpc_opcode*)nullptr;
        }();

    const uint32_t word = insn.instruction;
    insn.opcode = vsldoi128;
    memset(insn.operands, 0, sizeof(insn.operands));
    insn.operands[0] = ((word << 3) & 0x60) | ((word >> 21) & 0x1F); // VD128
    insn.operands[1] = ((word >> 4) & 0x40) | (word & 0x20) | ((word >> 16) & 0x1F); // VA128
    insn.operands[2] = ((word << 5) & 0x60) | ((word >> 11) & 0x1F); // VB128
    insn.operands[3] = (word >> 6) & 0xF; // SHB
    snprintf(insn.op_str, sizeof(insn.op_str), "v%u,v%u,v%u,%u", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
}

bool Recompiler::Recompile(const Function& fn)
{
    auto base = fn.base;
    auto end = base + fn.size;
    auto* data = (uint32_t*)image.Find(base);

    static std::unordered_set<size_t> labels;
    labels.clear();

    for (size_t addr = base; addr < end; addr += 4)
    {
        const uint32_t instruction = ByteSwap(*(uint32_t*)((char*)data + addr - base));
        if (!PPC_BL(instruction))
        {
            const size_t op = PPC_OP(instruction);
            if (op == PPC_OP_B)
                labels.emplace(addr + PPC_BI(instruction));
            else if (op == PPC_OP_BC)
                labels.emplace(addr + PPC_BD(instruction));
        }

        auto switchTable = config.switchTables.find(addr);
        if (switchTable != config.switchTables.end())
        {
            for (auto label : switchTable->second.labels)
                labels.emplace(label);
        }

        auto midAsmHook = config.midAsmHooks.find(addr);
        if (midAsmHook != config.midAsmHooks.end())
        {
            if (midAsmHook->second.returnOnFalse || midAsmHook->second.returnOnTrue ||
                midAsmHook->second.jumpAddressOnFalse != NULL || midAsmHook->second.jumpAddressOnTrue != NULL)
            {
                print("extern bool ");
            }
            else
            {
                print("extern void ");
            }

            print("{}(", midAsmHook->second.name);
            for (auto& reg : midAsmHook->second.registers)
            {
                if (out.back() != '(')
                    out += ", ";

                switch (reg[0])
                {
                case 'c':
                    if (reg == "ctr")
                        print("PPCRegister& ctr");
                    else
                        print("PPCCRRegister& {}", reg);
                    break;

                case 'x':
                    print("PPCXERRegister& xer");
                    break;

                case 'r':
                    print("PPCRegister& {}", reg);
                    break;

                case 'f':
                    if (reg == "fpscr")
                        print("PPCFPSCRRegister& fpscr");
                    else
                        print("PPCRegister& {}", reg);
                    break;

                case 'v':
                    print("PPCVRegister& {}", reg);
                    break;
                }
            }

            println(");\n");

            if (midAsmHook->second.jumpAddress != NULL)
                labels.emplace(midAsmHook->second.jumpAddress);       
            if (midAsmHook->second.jumpAddressOnTrue != NULL)
                labels.emplace(midAsmHook->second.jumpAddressOnTrue);    
            if (midAsmHook->second.jumpAddressOnFalse != NULL)
                labels.emplace(midAsmHook->second.jumpAddressOnFalse);
        }
    }

    auto symbol = image.symbols.find(fn.base);
    std::string name;
    if (symbol != image.symbols.end())
    {
        name = symbol->name;
    }
    else
    {
        name = fmt::format("sub_{}", fn.base);
    }

#ifdef XENON_RECOMP_USE_ALIAS
    println("__attribute__((alias(\"__imp__{}\"))) PPC_WEAK_FUNC({});", name, name);
#endif

    println("PPC_FUNC_IMPL(__imp__{}) {{", name);
    println("\tPPC_FUNC_PROLOGUE();");
    emittingInContext = config.nonVolatileRegistersAsLocalVariables && contextFunctions.count(fn.base);
    if (emittingInContext)
        println("\t// non-volatile registers stay in ctx here (see ppc_context_functions.txt)");

    auto switchTable = config.switchTables.end();
    bool allRecompiled = true;
    CSRState csrState = CSRState::Unknown;

    // TODO: the printing scheme here is scuffed
    RecompilerLocalVariables localVariables;
    static std::string tempString;
    tempString.clear();
    std::swap(out, tempString);

    ppc_insn insn;
    while (base < end)
    {
        if (labels.find(base) != labels.end())
        {
            println("loc_{:X}:", base);

            // Anyone could jump to this label so we wouldn't know what the CSR state would be.
            csrState = CSRState::Unknown;
        }

        if (switchTable == config.switchTables.end())
            switchTable = config.switchTables.find(base);

        ppc::Disassemble(data, 4, base, insn);

        if (insn.opcode != nullptr && PPC_OP(insn.instruction) == 4 && (insn.instruction & 0x10) != 0 && insn.opcode->id != PPC_INST_VSLDOI128)
            DecodeVsldoi128(insn);

        if (insn.opcode == nullptr)
        {
            println("\t// {}", insn.op_str);
#if 1
            if (*data != 0)
            {
                println("\tPPC_UNIMPLEMENTED(0x{:X}, \"undecodable 0x{:08X}\");", base, ByteSwap(*data));
                problem("{:X} (in {:X}): can't decode instruction word {:08X}", base, fn.base, ByteSwap(*data));
                allRecompiled = false;
            }
#endif
        }
        else
        {
            if (insn.opcode->id == PPC_INST_BCTR && switchTable == config.switchTables.end() && LooksLikeJumpTable(image, fn, data, base))
                problem("{:X} (in {:X}): looks like a switch jump table with no switch table entry", base, fn.base);

            if (!Recompile(fn, base, insn, data, switchTable, localVariables, csrState))
            {
                println("\tPPC_UNIMPLEMENTED(0x{:X}, \"{}\");", base, insn.opcode->name);
                problem("{:X} (in {:X}): {} isn't implemented", base, fn.base, insn.opcode->name);
                allRecompiled = false;
            }
        }

        base += 4;
        ++data;
    }

    // A function whose last instruction can fall through runs on into the code after it, which on
    // the console is the next function: that's a tail call. (memset's 1-3 byte tail is the known
    // case: generated as is, the function returned early.) With no function there, it's a problem.
    if (fn.size != 0)
    {
        const uint32_t last = ByteSwap(*(data - 1));
        bool fallsThrough = true;
        if (PPC_OP(last) == PPC_OP_B && !PPC_BL(last))
            fallsThrough = false; // b
        else if (PPC_OP(last) == PPC_OP_CTR && !PPC_BL(last) && (PPC_BO(last) & 0x14) == 0x14 && (PPC_XOP(last) == 16 || PPC_XOP(last) == 528))
            fallsThrough = false; // blr, bctr
        else if (last == 0 || (last >> 26) == 3 && ((last >> 21) & 0x1F) == 31)
            fallsThrough = false; // padding, twi 31 (always traps)
        else if ((last >> 26) == 31 && ((last >> 1) & 0x3FF) == 4 && ((last >> 21) & 0x1F) == 31)
            fallsThrough = false; // tw 31
        else if (PPC_BL(last) && (PPC_OP(last) == PPC_OP_B ||
            ((PPC_OP(last) == PPC_OP_BC || PPC_OP(last) == PPC_OP_CTR) && (PPC_BO(last) & 0x14) == 0x14)))
            fallsThrough = false; // ends in an unconditional call: to a routine that doesn't return (an assert,
                                  // KeBugCheck). If a port's hook of it returns, returning here is safer than
                                  // running on. A conditional call's not-taken path does run on, as a tail call.

        if (fallsThrough)
        {
            auto next = image.symbols.find(end);
            if (next != image.symbols.end() && next->address == end && next->type == Symbol_Function)
            {
                println("\t// falls through into {}", next->name);
                auto ctxFn = contextFunctions.find(end);
                if (config.nonVolatileRegistersAsLocalVariables && !emittingInContext && ctxFn != contextFunctions.end())
                {
                    // Same copy to ctx and back as printFunctionCall does for a call.
                    std::vector<std::string> names;
                    for (size_t k = 0; k < 118; ++k)
                    {
                        if (!ctxFn->second.test(k))
                            continue;
                        if (k < 18) { localVariables.r[k + 14] = true; names.push_back(fmt::format("r{}", k + 14)); }
                        else if (k < 36) { localVariables.f[k - 18 + 14] = true; names.push_back(fmt::format("f{}", k - 18 + 14)); }
                        else if (k < 54) { localVariables.v[k - 36 + 14] = true; names.push_back(fmt::format("v{}", k - 36 + 14)); }
                        else { localVariables.v[k - 54 + 64] = true; names.push_back(fmt::format("v{}", k - 54 + 64)); }
                    }
                    println("\t{{ // {} keeps these registers in ctx", next->name);
                    for (auto& n : names)
                        println("\t\tconst auto saved_{0} = ctx.{0}; ctx.{0} = {0};", n);
                    println("\t\t{}(ctx, base);", next->name);
                    for (auto& n : names)
                        println("\t\t{0} = ctx.{0}; ctx.{0} = saved_{0};", n);
                    println("\t}}");
                }
                else
                    println("\t{}(ctx, base);", next->name);
                println("\treturn;");
                ++fallThroughs;
            }
            else
            {
                println("\tPPC_UNRESOLVED_BRANCH(0x{:X}, 0x{:X});", base - 4, end);
                problem("{:X} (in {:X}): the function runs off its end at {:X}, and no function starts there", base - 4, fn.base, end);
            }
        }
    }

    println("}}\n");

#ifndef XENON_RECOMP_USE_ALIAS
    println("PPC_WEAK_FUNC({}) {{", name);
    println("\t__imp__{}(ctx, base);", name);
    println("}}\n");
#endif

    std::swap(out, tempString);
    if (localVariables.ctr)
        println("\tPPCRegister ctr{{}};");   
    if (localVariables.xer)
        println("\tPPCXERRegister xer{{}};");
    if (localVariables.reserved)
        println("\tPPCRegister reserved{{}};");

    for (size_t i = 0; i < 8; i++)
    {
        if (localVariables.cr[i])
            println("\tPPCCRRegister cr{}{{}};", i);
    }

    for (size_t i = 0; i < 32; i++)
    {
        if (localVariables.r[i])
            println("\tPPCRegister r{}{{}};", i);
    }

    for (size_t i = 0; i < 32; i++)
    {
        if (localVariables.f[i])
            println("\tPPCRegister f{}{{}};", i);
    }

    for (size_t i = 0; i < 128; i++)
    {
        if (localVariables.v[i])
            println("\tPPCVRegister v{}{{}};", i);
    }

    if (localVariables.env)
        println("\tPPCContext env{{}};"); 
    
    if (localVariables.temp)
        println("\tPPCRegister temp{{}};"); 
    
    if (localVariables.vTemp)
        println("\tPPCVRegister vTemp{{}};");

    if (localVariables.ea)
        println("\tuint32_t ea{{}};");

    out += tempString;

    emittingInContext = false;
    return allRecompiled;
}

bool Recompiler::Recompile(const std::filesystem::path& headerFilePath)
{
    out.reserve(10 * 1024 * 1024);

    {
        println("#pragma once");

        println("#ifndef PPC_CONFIG_H_INCLUDED");
        println("#define PPC_CONFIG_H_INCLUDED\n");

        if (config.skipLr)
            println("#define PPC_CONFIG_SKIP_LR");      
        if (config.ctrAsLocalVariable)
            println("#define PPC_CONFIG_CTR_AS_LOCAL");      
        if (config.xerAsLocalVariable)
            println("#define PPC_CONFIG_XER_AS_LOCAL");      
        if (config.reservedRegisterAsLocalVariable)
            println("#define PPC_CONFIG_RESERVED_AS_LOCAL");      
        if (config.skipMsr)
            println("#define PPC_CONFIG_SKIP_MSR");      
        if (config.crRegistersAsLocalVariables)
            println("#define PPC_CONFIG_CR_AS_LOCAL");
        if (config.hardwareFences)
            println("#define PPC_CONFIG_HARDWARE_FENCES");
        if (config.nonArgumentRegistersAsLocalVariables)
            println("#define PPC_CONFIG_NON_ARGUMENT_AS_LOCAL");   
        if (config.nonVolatileRegistersAsLocalVariables)
        {
            println("#define PPC_CONFIG_NON_VOLATILE_AS_LOCAL");
            // The context functions (nonvolatile_context.cpp) still need the fields.
            println("#define PPC_CONFIG_NON_VOLATILE_IN_CONTEXT");
        }

        println("");

        println("#define PPC_IMAGE_BASE 0x{:X}ull", image.base);
        println("#define PPC_IMAGE_SIZE 0x{:X}ull", image.size);
        
        // Extract the address of the minimum code segment to store the function table at.
        size_t codeMin = ~0;
        size_t codeMax = 0;

        for (auto& section : image.sections)
        {
            if ((section.flags & SectionFlags_Code) != 0)
            {
                if (section.base < codeMin)
                    codeMin = section.base;

                if ((section.base + section.size) > codeMax)
                    codeMax = (section.base + section.size);
            }
        }

        println("#define PPC_CODE_BASE 0x{:X}ull", codeMin);
        println("#define PPC_CODE_SIZE 0x{:X}ull", codeMax - codeMin);

        // PPC_LOOKUP_FUNC(base, y) is base + y * 2 + (table - 2 * PPC_CODE_BASE). x64 folds that into a
        // single [base + y*2 + disp32] when the constant fits in 32 bits; otherwise every indirect call
        // and its table load need an extra 64-bit constant. With code at 0x82xxxxxx the table must sit
        // at or above 2 * PPC_CODE_BASE - 2^31 for that.
        const uint64_t tableBase = config.functionTableAddress != 0 ? config.functionTableAddress : uint64_t(image.base) + image.size;
        const int64_t displacement = int64_t(tableBase) - 2 * int64_t(codeMin);
        if (config.functionTableAddress != 0)
            println("#define PPC_FUNC_TABLE_BASE 0x{:X}ull", tableBase);
        if (displacement < INT32_MIN || displacement > INT32_MAX)
        {
            const uint64_t lowest = (2 * uint64_t(codeMin) - 0x80000000ull + 0xFFFF) & ~0xFFFFull;
            const uint64_t highest = std::min<uint64_t>(2 * uint64_t(codeMin) + 0x7FFFFFFFull, 0x100000000ull - 2 * uint64_t(codeMax - codeMin)) & ~0xFFFFull;
            fmt::println("Note: the indirect-call table at 0x{:X} is too far for a 32-bit displacement; a function_table_address from 0x{:X} to 0x{:X} (where the port has 0x{:X} free bytes) lets every indirect call use one",
                tableBase, lowest, highest, 2 * uint64_t(codeMax - codeMin));
        }
        if (tableBase + 2 * uint64_t(codeMax - codeMin) > 0x100000000ull)
        {
            problem("the indirect-call table (0x{:X}, 0x{:X} bytes) runs past the 4 GB guest space", tableBase, 2 * (codeMax - codeMin));
        }

        println("");

        println("#ifdef PPC_INCLUDE_DETAIL");
        println("#include \"ppc_detail.h\"");
        println("#endif");

        println("\n#endif");

        SaveCurrentOutData("ppc_config.h");
    }

    {
        println("#pragma once");

        println("#include \"ppc_config.h\"\n");
        
        std::ifstream stream(headerFilePath);
        if (stream.good())
        {
            std::stringstream ss;
            ss << stream.rdbuf();
            out += ss.str();
        }

        SaveCurrentOutData("ppc_context.h");
    }

    {
        println("#pragma once\n");
        println("#include \"ppc_config.h\"");
        println("#include \"ppc_context.h\"\n");

        for (auto& symbol : image.symbols)
            println("PPC_EXTERN_FUNC({});", symbol.name);

        SaveCurrentOutData("ppc_recomp_shared.h");
    }

    {
        println("#include \"ppc_recomp_shared.h\"\n");

        println("PPCFuncMapping PPCFuncMappings[] = {{");
        for (auto& symbol : image.symbols)
            println("\t{{ 0x{:X}, {} }},", symbol.address, symbol.name);

        println("\t{{ 0, nullptr }}");
        println("}};");

        SaveCurrentOutData("ppc_func_mapping.cpp");
    }

    if (config.elideEmptyFunctions)
    {
        for (auto& fn : functions)
        {
            auto* data = (const uint32_t*)image.Find(fn.base);
            if (fn.size == 4 && data != nullptr && ByteSwap(*data) == 0x4E800020 && !config.keepFunctions.count(fn.base) &&
                !config.midAsmHooks.count(fn.base))
            {
                emptyFunctions.emplace(fn.base);
            }
        }

        std::vector<size_t> sorted(emptyFunctions.begin(), emptyFunctions.end());
        std::sort(sorted.begin(), sorted.end());
        println("# Functions that are only blr; calls to them are left out of the recompiled code.");
        println("# A port that hooks one of these must add it to keep_functions in its config.");
        for (size_t address : sorted)
            println("{:X}", address);
        SaveCurrentOutData("ppc_elided_functions.txt");
        fmt::println("Eliding calls to {} empty functions", sorted.size());
    }

    if (config.nonVolatileRegistersAsLocalVariables)
        FindContextFunctions();

    if (config.chunkByAddress != 0)
    {
        RecompileChunkedByAddress();
    }
    else
    {
        const size_t firstFileIndex = cppFileIndex;
        for (size_t i = 0; i < functions.size(); i++)
        {
            if ((i % 256) == 0)
            {
                SaveCurrentOutData();
                println("#include \"ppc_recomp_shared.h\"\n");
            }

            if ((i % 2048) == 0 || (i == (functions.size() - 1)))
                fmt::println("Recompiling functions... {}%", static_cast<float>(i + 1) / functions.size() * 100.0f);

            Recompile(functions[i]);
        }

        SaveCurrentOutData();

        std::set<std::string> written;
        for (size_t i = firstFileIndex; i < cppFileIndex; i++)
            written.insert(fmt::format("ppc_recomp.{}.cpp", i));
        if (const size_t removed = RemoveStaleChunkFiles(written))
            fmt::println("Removed {} stale chunk file(s)", removed);
    }

    if (fallThroughs != 0)
        fmt::println("{} function(s) fall through into the next one (emitted as tail calls)", fallThroughs);

    if (!problems.empty())
    {
        fmt::println("{} {} (each traps at run time):", problems.size(), problems.size() == 1 ? "problem" : "problems");
        for (auto& p : problems)
            fmt::println("  {}", p);
        if (!config.allowUnresolved)
        {
            fmt::println("ERROR: failing because of the problems above (set allow_unresolved = true in [main] to accept them)");
            return false;
        }
    }
    return true;
}

void Recompiler::RecompileChunkedByAddress()
{
    size_t codeStart = SIZE_MAX;
    for (const auto& section : image.sections)
    {
        if (section.flags & SectionFlags_Code)
            codeStart = (std::min)(codeStart, size_t(section.base));
    }

    // functions is sorted by address, so each chunk is a contiguous run.
    std::map<size_t, std::vector<size_t>> chunks;
    for (size_t i = 0; i < functions.size(); i++)
        chunks[(functions[i].base - codeStart) / config.chunkByAddress].push_back(i);

    std::unordered_set<std::string_view> names;
    for (const auto& symbol : image.symbols)
        names.insert(symbol.name);

    auto isIdentifierStart = [](char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; };
    auto isIdentifier = [&](char c) { return isIdentifierStart(c) || (c >= '0' && c <= '9'); };

    std::set<std::string> written;
    size_t done = 0, nextReport = 0;
    for (const auto& [index, members] : chunks)
    {
        for (size_t i : members)
        {
            Recompile(functions[i]);
            if (++done >= nextReport || done == functions.size())
            {
                fmt::println("Recompiling functions... {}%", static_cast<float>(done) / functions.size() * 100.0f);
                nextReport = done + 2048;
            }
        }

        // Declare every function this chunk names (calls, tail calls, its own definitions).
        std::set<std::string_view> referenced;
        const std::string body = std::move(out);
        out.clear();
        for (size_t p = 0; p < body.size(); )
        {
            if (!isIdentifierStart(body[p]) || (p != 0 && isIdentifier(body[p - 1])))
            {
                ++p;
                continue;
            }
            size_t e = p;
            while (e < body.size() && isIdentifier(body[e]))
                ++e;
            auto name = names.find(std::string_view(body).substr(p, e - p));
            if (name != names.end())
                referenced.insert(*name);
            p = e;
        }

        println("#include \"ppc_config.h\"");
        println("#include \"ppc_context.h\"\n");
        for (auto name : referenced)
            println("PPC_EXTERN_FUNC({});", name);
        println("");
        out += body;

        const std::string fileName = fmt::format("ppc_recomp.{}.cpp", index);
        SaveCurrentOutData(fileName);
        written.insert(fileName);
    }

    const size_t removed = RemoveStaleChunkFiles(written);
    fmt::println("{} chunk file(s) by address (0x{:X} bytes of guest code each){}", chunks.size(), config.chunkByAddress,
        removed != 0 ? fmt::format("; removed {} stale chunk file(s)", removed) : "");
}

// Removes ppc_recomp.<digits>.cpp files this run didn't write (left by the other layout or by a
// bigger chunk count): a port that globs ppc_recomp.*.cpp would otherwise build them and get
// duplicate functions. Nothing else in the output folder is touched.
size_t Recompiler::RemoveStaleChunkFiles(const std::set<std::string>& written)
{
    std::string directoryPath = config.directoryPath;
    if (!directoryPath.empty())
        directoryPath += "/";
    const std::filesystem::path outDirectory = directoryPath + config.outDirectoryPath;
    size_t removed = 0;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(outDirectory, ec))
    {
        const std::string fileName = entry.path().filename().string();
        if (fileName.size() > 15 && fileName.compare(0, 11, "ppc_recomp.") == 0 && fileName.compare(fileName.size() - 4, 4, ".cpp") == 0 &&
            std::all_of(fileName.begin() + 11, fileName.end() - 4, [](char c) { return c >= '0' && c <= '9'; }) &&
            !written.count(fileName))
        {
            std::filesystem::remove(entry.path(), ec);
            ++removed;
        }
    }
    return removed;
}

void Recompiler::SaveCurrentOutData(const std::string_view& name)
{
    if (!out.empty())
    {
        std::string cppName;

        if (name.empty())
        {
            cppName = fmt::format("ppc_recomp.{}.cpp", cppFileIndex);
            ++cppFileIndex;
        }

        bool shouldWrite = true;

        // Check if an identical file already exists first to not trigger recompilation
        std::string directoryPath = config.directoryPath;
        if (!directoryPath.empty())
            directoryPath += "/";

        std::string filePath = fmt::format("{}{}/{}", directoryPath, config.outDirectoryPath, name.empty() ? cppName : name);
        FILE* f = fopen(filePath.c_str(), "rb");
        if (f)
        {
            static std::vector<uint8_t> temp;

            fseek(f, 0, SEEK_END);
            long fileSize = ftell(f);
            if (fileSize == out.size())
            {
                fseek(f, 0, SEEK_SET);
                temp.resize(fileSize);
                fread(temp.data(), 1, fileSize, f);

                shouldWrite = !XXH128_isEqual(XXH3_128bits(temp.data(), temp.size()), XXH3_128bits(out.data(), out.size()));
            }
            fclose(f);
        }

        if (shouldWrite)
        {
            std::error_code dirError;
            std::filesystem::create_directories(std::filesystem::path(filePath).parent_path(), dirError);
            f = fopen(filePath.c_str(), "wb");
            if (!f)
            {
                fmt::println("ERROR: can't write {}", filePath);
                std::exit(1);
            }
            fwrite(out.data(), 1, out.size(), f);
            fclose(f);
        }

        out.clear();
    }
}
