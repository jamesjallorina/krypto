#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "../include/krypto/krpyto.hpp"
#include <type_traits>

TEST_CASE("test context","[context]")
{
	krypto::context ctx(krypto::ssl_method::tls);
	CHECK(ctx.is_valid());
}