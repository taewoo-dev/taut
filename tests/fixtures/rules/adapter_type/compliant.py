from app.contracts import PaymentData


async def pay(request: PaymentData) -> PaymentData:
    return request
