// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "catch2/catch.hpp"
#include "StringUtils.hpp"
#include "DynamicFunction.hpp"
#include "WorkQueue.hpp"

#include <sysinfoapi.h>

#include <array>
#include <chrono>
using namespace std::chrono_literals;

// Tests for StringUtils.hpp

TEST_CASE("ByteBufferToHexString format correctly", "[stringUtils]")
{
    CHECK(ByteBufferToHexString(std::array<uint8_t, 3>{8, 10, 20}) == std::wstring(L"080a14"));
    CHECK(ByteBufferToHexString(std::array<uint8_t, 0>{}) == std::wstring());
}

TEST_CASE("HexStringToByteBuffer parse correctly", "[stringUtils]")
{
    CHECK(HexStringToByteBuffer(L"080a14") == std::vector<uint8_t>{8, 10, 20});
    CHECK(HexStringToByteBuffer(L"") == std::vector<uint8_t>{});
    CHECK_THROWS(HexStringToByteBuffer(L"080a1"));
}

TEST_CASE("GuidToString format correctly", "[stringUtils]")
{
    constexpr GUID guid{0xfef2f808, 0xf267, 0x4728, {0xa0, 0xc5, 0x0a, 0x62, 0x40, 0xd0, 0x1b, 0x33}};
    CHECK(GuidToString(guid) == std::wstring(L"{FEF2F808-F267-4728-A0C5-0A6240D01B33}"));
}

TEST_CASE("BssidToString format correctly", "[stringUtils]")
{
    CHECK(BssidToString(std::array<uint8_t, 6>{216, 236, 94, 16, 126, 22}) == std::wstring(L"d8:ec:5e:10:7e:16"));
    CHECK(BssidToString(std::array<uint8_t, 6>{0, 0, 1, 0, 0, 0}) == std::wstring(L"00:00:01:00:00:00"));
}

TEST_CASE("SsidToLogString format correctly", "[stringUtils]")
{
    CHECK(SsidToLogString(std::array<uint8_t, 7>{'m', 'y', ' ', 'w', 'i', 'f', 'i'}) == std::wstring(L"'my wifi' [226422226d792077696669]"));
    CHECK(SsidToLogString(std::array<uint8_t, 0>{}) == std::wstring(L"'' []"));
}

TEST_CASE("ListEnumToHexString format correctly", "[stringUtils]")
{
    enum class Breakfast : uint32_t
    {
        Croissant = 0xabc11100,
        Chocolatine = 0xdef22200,
        Coffee = 0xabcdef00
    };

    enum class Pizza
    {
        Cheese,
        Peperoni
    };

    {
        auto a = std::array{Breakfast::Croissant, Breakfast::Chocolatine};
        CHECK(ListEnumToHexString(std::span(a)) == std::wstring(L"abc11100 def22200"));
    }
    {
        auto v = std::vector{Breakfast::Coffee};
        CHECK(ListEnumToHexString(std::span(v)) == std::wstring(L"abcdef00"));
    }
    {
        auto a = std::vector<Breakfast>{};
        CHECK(ListEnumToHexString(std::span(a)) == std::wstring(L""));
    }
    {
        auto v = std::vector{Pizza::Cheese};
        CHECK(ListEnumToHexString(std::span(v), L"-", 4) == std::wstring(L"0000"));
    }
    {
        auto v = std::vector{Pizza::Peperoni, Pizza::Cheese};
        CHECK(ListEnumToHexString(std::span(v), L"-", 4) == std::wstring(L"0001-0000"));
    }
}

TEST_CASE("Dynamic function basic behavior works", "[dynamicFunction]")
{
    SECTION("Loading an valid function from a valid module works")
    {
        CHECK_NOTHROW([]() {
            DynamicFunction<decltype(::GetTickCount)> dynFun{L"kernel32.dll", "GetTickCount"};
            dynFun();
        }());
    }

    SECTION("Loading from a non-existing module throws")
    {
        CHECK_THROWS([]() { DynamicFunction<decltype(::GetTickCount)> dynFun{L"dummy.dll", "GetNativeSystemInfo"}; }());
    }

    SECTION("Loading a non-existing function throws")
    {
        CHECK_THROWS([]() { DynamicFunction<decltype(::GetTickCount)> dynFun{L"kernel32.dll", "dummy"}; }());
    }
}

TEST_CASE("Work queues execute work items", "[workQueue]")
{

    SECTION("A work item is exectuted")
    {
        SerializedWorkQueue<std::function<void(void)>> wq;
        wil::slim_event event;
        wq.Submit([&] { event.SetEvent(); });

        CHECK(event.wait(50 /* ms */));
    }

    SECTION("Any callable type is supported and return value are ignored")
    {
        struct Work {
            int operator()()
            {
                event.SetEvent();
                return 42;
            }
            wil::slim_event& event;
        };

        SerializedWorkQueue<Work> wq;
        wil::slim_event event;
        wq.Submit(Work{event});
        CHECK(event.wait(50 /* ms */));
    }

    SECTION("Work items are executed asychronously in a different thread")
    {
        SerializedWorkQueue<std::function<void(void)>> wq;
        wil::slim_event event;
        wil::slim_event event2;
        wq.Submit([&] {
            event2.wait();
            event.SetEvent();
        });

        event2.SetEvent();
        CHECK(event.wait(50 /* ms */));
    }
}

TEST_CASE("Work item cancellation works", "[workQueue]")
{
    // Check that Cancel wait for currently running work items completion and cancel any pending one
    const int workScheduled = 10;
    std::atomic_int workStarted{0};
    std::atomic_int workCompleted{0};
    auto f = [&] {
        ++workStarted;
        std::this_thread::sleep_for(10ms);
        ++workCompleted;
    };

    WorkQueue<std::function<void()>, 2, 2> wq;
    for (auto i = 0; i < workScheduled; ++i)
    {
        wq.Submit(f);
    }
    wq.Cancel();

    CHECK(workStarted == workCompleted);
    CHECK(workStarted <= workScheduled);
}

TEST_CASE("Work item are serialized in a serialized queue", "[workQueue]")
{
    // Work items are serialized in a serialized queue
    SerializedWorkQueue<std::function<void(void)>> wq;
    wil::slim_event event;
    std::atomic_bool firstWorkComplete;
    bool testPassed = false;

    wq.Submit([&] {
        std::this_thread::sleep_for(10ms);
        firstWorkComplete = true;
    });
    wq.Submit([&] {
        testPassed = firstWorkComplete;
        event.SetEvent();
    });

    CHECK(event.wait(50 /* ms */));
    CHECK(testPassed);
}

TEST_CASE("Light stress", "[workQueue]")
{
    SECTION("All work item run in light stress situation")
    {
        WorkQueue<std::function<void(void)>, 5, 5> wq;
        wil::slim_event event;
        std::atomic<int> count;
        constexpr auto numTasks = 1000;

        for (auto i = 0; i < numTasks; ++i)
        {
            wq.Submit([&] {
                auto v = ++count;
                if (v == numTasks)
                {
                    event.SetEvent();
                }
            });
        }

        CHECK(event.wait(500 /* ms */));
    }

    SECTION("All work item are serialized in light stress situation")
    {
        SerializedWorkQueue<std::function<void(void)>> wq;
        wil::slim_event event;
        auto count = 0;
        constexpr auto numTasks = 1000;
        bool testPassed = true;

        for (auto i = 0; i < numTasks; ++i)
        {
            wq.Submit([&, id = i] {
                if (id != count++)
                {
                    testPassed = false;
                }
                if (count == numTasks)
                {
                    event.SetEvent();
                }
            });
        }

        CHECK(event.wait(500 /* ms */));
        CHECK(testPassed);
    }
}

TEST_CASE("Work runner basic tests", "[workQueue]")
{
    SECTION("Work items are executed")
    {
        SerializedWorkRunner wq;
        wil::slim_event event;
        wil::slim_event event2;
        wq.Run([&] {
            event2.wait();
            event.SetEvent();
        });

        event2.SetEvent();
        CHECK(event.wait(50 /* ms */));
    }

    SECTION("Return values are ignored if not waited for")
    {
        SerializedWorkRunner wq;
        // The task can return a value, which is ignored
        wil::slim_event event;
        wq.Run([&] {
            event.SetEvent();
            return "pizza";
        });
        CHECK(event.wait(50 /* ms */));
    }

    SECTION("One can wait for the return value")
    {
        SerializedWorkRunner wq;
        const auto r = wq.RunAndWait([&] { return 42; });
        CHECK(r == 42);
    }

    SECTION("One can wait without a return value")
    {
        SerializedWorkRunner wq;
        int a = 0;
        wq.RunAndWait([&] { a = 42; });
        CHECK(a == 42);
    }
}