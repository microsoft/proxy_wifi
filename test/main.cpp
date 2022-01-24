// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define CATCH_CONFIG_RUNNER
#include "catch2/catch.hpp"

#include "ProxyWifi/Logs.hpp"

int main(int argc, char* argv[])
{
    ProxyWifi::Log::AddLogger(std::make_unique<ProxyWifi::Log::ConsoleLogger>());
    return Catch::Session().run(argc, argv);
}
