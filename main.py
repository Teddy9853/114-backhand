from typing import Annotated
from fastapi import FastAPI,Path , Body, Cookie, Form
from pydantic import BaseModel, Field

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from .google_oauth import verify_google_id_token
from .auth_utils import create_access_token, get_current_user_email


class Item(BaseModel):
    name: str
    description: str | None = Field(
        default = None, title = "The description of the item", max_length = 300
    )
    price: float = Field(gt = 0, description = "the price must be gra=eater than zero")
    tax: float | None = None

app = FastAPI(title="資工系 114-Backend 示範專案")

@app.post("/login")
async def login(
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
):
    """Simple placeholder login that issues a JWT for the submitted username."""
    access_token = create_access_token(data={"sub": username})
    return {"access_token": access_token, "token_type": "bearer", "username": username}


# 定義前端傳入的資料格式
class TokenRequest(BaseModel):
    id_token: str

# 1. Google 登入換取自家 JWT 的接口
@app.post("/auth/google", summary="Google OAuth 登入驗證")
async def google_auth(request: TokenRequest):
    """
    接收前端拿到的 Google id_token，驗證後發放本系統的 JWT
    """
    # Step A: 呼叫 google_oauth.py 驗證身分
    user_info = verify_google_id_token(request.id_token)
    
    # Step B: 取得使用者 email (通常作為 User Unique ID)
    user_email = user_info.get("email")
    if not user_email:
        raise HTTPException(status_code=400, detail="Google 帳號未提供 Email")

    # Step C: (可選) 在此處檢查資料庫，若無此使用者則新增
    # user = db.query(User).filter(User.email == user_email).first()
    
    # Step D: 呼叫 auth_utils.py 簽發自家的 Access Token
    access_token = create_access_token(data={"sub": user_email})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "name": user_info.get("name"),
            "email": user_email,
            "picture": user_info.get("picture")
        }
    }

# 2. 受保護的路由 (需要 JWT 才能進入)
@app.get("/users/me", summary="取得當前使用者資訊")
async def read_users_me(current_user: str = Depends(get_current_user_email)):
    """
    只有在 Header 帶上有效的 Authorization: Bearer <JWT> 才能存取
    """
    return {
        "msg": "成功通過 JWT 驗證",
        "user_email": current_user
    }

# 3. 測試用公開路由
@app.get("/")
def root():
    return {"message": "Hello FastAPI OAuth Demo"}

@app.get("/items/{item_id}")
async def read_item(item_id):
    return{"item_id":item_id}

@app.get("/items/")
async def read_items(ads_id: Annotated[str | None, Cookie()]):
    return{"ads_id": ads_id}
"""
@app.get("/items/")
async def read_item(skip: int = 0, limit: int = 10):
    return fake_items_db[skip: skip + limit]

fake_items_db = [
    {"item_name": "Foo"},
    {"item_name": "Bar"},
    {"item_name": "Baz"}
]
"""
@app.post("/items/")
async def create_item(item: Item) -> Item:
    return item
"""
@app.post("/items/")
async def create_item(item: Item):
    item_dict = item.model_dump() #item.dict()
    if item.tax is not None:
        price_with_tax = item.price + item.tax
        item_dict.update({"price_with_tax": price_with_tax})
    return item_dict
"""
@app.put("/items/{item_id}")
async def update_item(item_id: int, item: Annotated[Item, Body(embed = True)]):
    results = {"item_id": item_id, "item": item}
    return results


"""
@app.put("/items/{item_id}")
async def update_item(
    item_id: Annotated[ int, Path(title = "The ID of the item to get", ge = 0, le = 1000)], 
    item: Item | None = None, 
    q: str | None = None,
):
    results = {"item_id": item_id}
    if q:
        results.update({"q":q})
    if item:
        results.update({"item": item})
    return results
"""

#@app.put("/items/{item_id}")
#async def update_item(item_id: int, item: Item, q: str | None = None):
#    result = {"item_id": item_id, **item.model_dump()}
#    if q:
#        result.update({"q":q})
#    return result
