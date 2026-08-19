import vendor_sdk


async def load() -> object:
    return await vendor_sdk.fetch()
