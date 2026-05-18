from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import databases
import sqlalchemy
from sqlalchemy import text
import os
import time
import json
import bcrypt
from jose import jwt, JWTError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ===== КОНФИГ =====
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:secret@db:5432/mydb")
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24 * 7  # 7 дней

# ===== RATE LIMITER =====
limiter = Limiter(key_func=get_remote_address)

# ===== БД =====
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

accounts_table = sqlalchemy.Table(
    "accounts", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("login", sqlalchemy.String(64), unique=True, nullable=False),
    sqlalchemy.Column("pass_hash", sqlalchemy.String(256), nullable=False),
    sqlalchemy.Column("pcoins", sqlalchemy.Integer, default=0),
)

posts_table = sqlalchemy.Table(
    "posts", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("author", sqlalchemy.String(64), nullable=False),
    sqlalchemy.Column("text", sqlalchemy.Text, default=""),
    sqlalchemy.Column("photo", sqlalchemy.Text, default=None, nullable=True),
    sqlalchemy.Column("likes", sqlalchemy.Integer, default=0),
    sqlalchemy.Column("liked_by", sqlalchemy.Text, default=""),
    sqlalchemy.Column("time_str", sqlalchemy.String(64), default=""),
    sqlalchemy.Column("created_at", sqlalchemy.BigInteger, default=lambda: int(time.time() * 1000)),
)

comments_table = sqlalchemy.Table(
    "comments", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("post_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("posts.id"), nullable=False),
    sqlalchemy.Column("author", sqlalchemy.String(64), nullable=False),
    sqlalchemy.Column("text", sqlalchemy.Text, nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.BigInteger, default=lambda: int(time.time() * 1000)),
)

ads_table = sqlalchemy.Table(
    "ads", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("author", sqlalchemy.String(64), nullable=False),
    sqlalchemy.Column("title", sqlalchemy.String(120), nullable=False),
    sqlalchemy.Column("text", sqlalchemy.Text, nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.BigInteger, default=lambda: int(time.time() * 1000)),
)

online_table = sqlalchemy.Table(
    "online", metadata,
    sqlalchemy.Column("login", sqlalchemy.String(64), primary_key=True),
    sqlalchemy.Column("last_seen", sqlalchemy.BigInteger, default=lambda: int(time.time() * 1000)),
)

roles_table = sqlalchemy.Table(
    "roles", metadata,
    sqlalchemy.Column("login", sqlalchemy.String(64), primary_key=True),
    sqlalchemy.Column("role", sqlalchemy.String(32), nullable=False),
)

timeouts_table = sqlalchemy.Table(
    "timeouts", metadata,
    sqlalchemy.Column("login", sqlalchemy.String(64), primary_key=True),
    sqlalchemy.Column("timeout_until", sqlalchemy.BigInteger, nullable=False),
)

snake_scores_table = sqlalchemy.Table(
    "snake_scores", metadata,
    sqlalchemy.Column("login", sqlalchemy.String(64), primary_key=True),
    sqlalchemy.Column("score", sqlalchemy.Integer, nullable=False, default=0),
    sqlalchemy.Column("updated_at", sqlalchemy.BigInteger, default=lambda: int(time.time() * 1000)),
)

music_tracks_table = sqlalchemy.Table(
    "music_tracks", metadata,
    sqlalchemy.Column("id", sqlalchemy.String(64), primary_key=True),
    sqlalchemy.Column("title", sqlalchemy.String(120), nullable=False),
    sqlalchemy.Column("artist", sqlalchemy.String(120), nullable=False),
    sqlalchemy.Column("author", sqlalchemy.String(64), nullable=False),
    sqlalchemy.Column("time_str", sqlalchemy.String(64), nullable=False),
    sqlalchemy.Column("has_gif", sqlalchemy.Boolean, default=False),
    sqlalchemy.Column("audio_data", sqlalchemy.Text, nullable=True),
    sqlalchemy.Column("cover_data", sqlalchemy.Text, nullable=True),
    sqlalchemy.Column("created_at", sqlalchemy.BigInteger, default=lambda: int(time.time() * 1000)),
)

engine = sqlalchemy.create_engine(DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://"))
metadata.create_all(engine)

app = FastAPI(title="Подвальные Пельмени API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)


# ===== JWT =====
def create_token(login: str) -> str:
    payload = {
        "sub": login,
        "exp": int(time.time()) + JWT_EXPIRE_HOURS * 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    if not credentials:
        raise HTTPException(401, "Требуется авторизация!")
    login = decode_token(credentials.credentials)
    if not login:
        raise HTTPException(401, "Токен недействителен или истёк!")
    acc = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == login)
    )
    if not acc:
        raise HTTPException(401, "Пользователь не найден!")
    return login


# ===== ПАРОЛИ =====
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


# ===== ХЕЛПЕРЫ =====
async def get_role(login: str) -> Optional[str]:
    row = await database.fetch_one(
        roles_table.select().where(roles_table.c.login == login)
    )
    return row["role"] if row else None

async def require_admin_or_mod(login: str):
    role = await get_role(login)
    if role not in ("admin", "moderator"):
        raise HTTPException(403, "Нет прав! Нужна роль админа или модератора.")
    return role

async def is_timed_out(login: str) -> bool:
    row = await database.fetch_one(
        timeouts_table.select().where(timeouts_table.c.login == login)
    )
    if not row:
        return False
    if row["timeout_until"] > int(time.time() * 1000):
        return True
    await database.execute(
        timeouts_table.delete().where(timeouts_table.c.login == login)
    )
    return False


# ===== LIFECYCLE =====
@app.get("/")
async def serve_root():
    return FileResponse("/app/static/pelmeni_v2__2_.html", media_type="text/html")

@app.on_event("startup")
async def startup():
    await database.connect()
    existing = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == "Fokza")
    )
    if not existing:
        await database.execute(
            accounts_table.insert().values(
                login="Fokza",
                pass_hash=hash_password("Password111adminqwerty"),
                pcoins=9999,
            )
        )
    existing_role = await database.fetch_one(
        roles_table.select().where(roles_table.c.login == "Fokza")
    )
    if not existing_role:
        await database.execute(
            roles_table.insert().values(login="Fokza", role="admin")
        )

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


# ===== МОДЕЛИ =====
class RegisterRequest(BaseModel):
    login: str
    password: str
    code: Optional[str] = ""

class LoginRequest(BaseModel):
    login: str
    password: str

class PostCreate(BaseModel):
    text: Optional[str] = ""
    photo: Optional[str] = None
    time_str: Optional[str] = ""

class CommentCreate(BaseModel):
    text: str

class AdCreate(BaseModel):
    title: str
    text: str

class PingRequest(BaseModel):
    login: str

class LikeRequest(BaseModel):
    pass  # пользователь берётся из токена

class PcoinsUpdate(BaseModel):
    login: str
    delta: int

class SpendRequest(BaseModel):
    amount: int

class AssignModRequest(BaseModel):
    target: str

class BanRequest(BaseModel):
    target: str

class TimeoutRequest(BaseModel):
    target: str
    duration_minutes: int

class DeletePostRequest(BaseModel):
    pass  # requester берётся из токена

class PostUpdate(BaseModel):
    text: Optional[str] = None
    photo: Optional[str] = None


class MusicTrackCreate(BaseModel):
    title: str
    artist: str
    has_gif: bool = False
    audio_data: Optional[str] = None
    cover_data: Optional[str] = None


# ===== AUTH =====
@app.post("/register")
@limiter.limit("5/minute")
async def register(request: Request, req: RegisterRequest):
    if not req.login.strip() or not req.password:
        raise HTTPException(400, "Заполни логин и пароль!")
    if len(req.login) > 32:
        raise HTTPException(400, "Логин слишком длинный!")
    if len(req.password) < 6:
        raise HTTPException(400, "Пароль слишком короткий! Минимум 6 символов.")
    existing = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == req.login)
    )
    if existing:
        raise HTTPException(400, "Такой логин уже занят!")
    approved = req.code == "TestCode167"
    await database.execute(
        accounts_table.insert().values(
            login=req.login,
            pass_hash=hash_password(req.password),
            pcoins=0,
        )
    )
    token = create_token(req.login)
    return {"ok": True, "approved": approved, "token": token, "login": req.login}

@app.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, req: LoginRequest):
    acc = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == req.login)
    )
    if not acc:
        raise HTTPException(400, "Такого аккаунта нет. Зарегистрируйся!")
    if not verify_password(req.password, acc["pass_hash"]):
        raise HTTPException(400, "Неверный пароль!")
    role = await get_role(req.login)
    token = create_token(req.login)
    return {"ok": True, "login": acc["login"], "pcoins": acc["pcoins"], "role": role, "token": token}

@app.get("/accounts")
async def get_accounts():
    rows = await database.fetch_all(accounts_table.select())
    return [{"login": r["login"]} for r in rows]

@app.get("/role/{login}")
async def get_user_role(login: str):
    role = await get_role(login)
    return {"login": login, "role": role}


# ===== ПОСТЫ =====
@app.get("/posts")
async def get_posts():
    rows = await database.fetch_all(posts_table.select().order_by(posts_table.c.created_at.desc()))
    result = []
    for p in rows:
        comments = await database.fetch_all(
            comments_table.select()
            .where(comments_table.c.post_id == p["id"])
            .order_by(comments_table.c.created_at.asc())
        )
        liked_by = json.loads(p["liked_by"]) if p["liked_by"] else []
        result.append({
            "id": p["id"],
            "author": p["author"],
            "text": p["text"],
            "photo": p["photo"],
            "likes": p["likes"],
            "likedBy": liked_by,
            "time": p["time_str"],
            "comments": [{"author": c["author"], "text": c["text"]} for c in comments],
        })
    return result

@app.post("/posts")
@limiter.limit("5/minute")
async def create_post(request: Request, post: PostCreate, current_user: str = Depends(get_current_user)):
    if not post.text and not post.photo:
        raise HTTPException(400, "Пост пустой!")
    if await is_timed_out(current_user):
        raise HTTPException(403, "Ты в тайм-ауте! Нельзя создавать посты.")
    post_id = await database.execute(
        posts_table.insert().values(
            author=current_user,
            text=post.text or "",
            photo=post.photo,
            likes=0,
            liked_by="[]",
            time_str=post.time_str,
            created_at=int(time.time() * 1000),
        )
    )
    return {"ok": True, "id": post_id}

@app.post("/posts/{post_id}/like")
async def toggle_like(post_id: int, current_user: str = Depends(get_current_user)):
    post = await database.fetch_one(
        posts_table.select().where(posts_table.c.id == post_id)
    )
    if not post:
        raise HTTPException(404, "Пост не найден")
    liked_by = json.loads(post["liked_by"]) if post["liked_by"] else []
    if current_user in liked_by:
        liked_by.remove(current_user)
    else:
        liked_by.append(current_user)
    await database.execute(
        posts_table.update()
        .where(posts_table.c.id == post_id)
        .values(likes=len(liked_by), liked_by=json.dumps(liked_by))
    )
    return {"ok": True, "likes": len(liked_by), "likedBy": liked_by}

@app.post("/posts/{post_id}/comments")
@limiter.limit("10/minute")
async def add_comment(request: Request, post_id: int, req: CommentCreate, current_user: str = Depends(get_current_user)):
    if not req.text.strip():
        raise HTTPException(400, "Комментарий пустой!")
    if await is_timed_out(current_user):
        raise HTTPException(403, "Ты в тайм-ауте! Нельзя комментировать.")
    await database.execute(
        comments_table.insert().values(
            post_id=post_id,
            author=current_user,
            text=req.text,
            created_at=int(time.time() * 1000),
        )
    )
    return {"ok": True}

@app.delete("/posts/{post_id}")
async def delete_post(post_id: int, current_user: str = Depends(get_current_user)):
    post = await database.fetch_one(
        posts_table.select().where(posts_table.c.id == post_id)
    )
    if not post:
        raise HTTPException(404, "Пост не найден")
    role = await get_role(current_user)
    is_owner = post["author"] == current_user
    is_superuser = current_user == "Fokzz_Back"
    is_admin_mod = role in ("admin", "moderator")
    if not (is_owner or is_superuser or is_admin_mod):
        raise HTTPException(403, "Нет прав для удаления этого поста!")
    await database.execute(
        comments_table.delete().where(comments_table.c.post_id == post_id)
    )
    await database.execute(
        posts_table.delete().where(posts_table.c.id == post_id)
    )
    return {"ok": True}

@app.patch("/posts/{post_id}")
async def edit_post(post_id: int, upd: PostUpdate, current_user: str = Depends(get_current_user)):
    post = await database.fetch_one(
        posts_table.select().where(posts_table.c.id == post_id)
    )
    if not post:
        raise HTTPException(404, "Пост не найден")
    if post["author"] != current_user:
        raise HTTPException(403, "Можно редактировать только свои посты!")
    values = {}
    if upd.text is not None:
        values["text"] = upd.text
    if upd.photo is not None:
        values["photo"] = upd.photo
    if not values:
        raise HTTPException(400, "Нечего обновлять")
    await database.execute(
        posts_table.update().where(posts_table.c.id == post_id).values(**values)
    )
    return {"ok": True}


# ===== ОБЪЯВЛЕНИЯ =====
@app.get("/ads")
async def get_ads():
    rows = await database.fetch_all(ads_table.select().order_by(ads_table.c.created_at.desc()))
    return [{"id": r["id"], "author": r["author"], "title": r["title"], "text": r["text"]} for r in rows]

@app.post("/ads")
@limiter.limit("3/minute")
async def create_ad(request: Request, ad: AdCreate, current_user: str = Depends(get_current_user)):
    acc = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == current_user)
    )
    if not acc:
        raise HTTPException(404, "Пользователь не найден")
    if acc["pcoins"] < 10:
        raise HTTPException(400, f"Недостаточно П-Баллов! Нужно 10, у тебя {acc['pcoins']}.")
    await database.execute(
        accounts_table.update()
        .where(accounts_table.c.login == current_user)
        .values(pcoins=acc["pcoins"] - 10)
    )
    ad_id = await database.execute(
        ads_table.insert().values(
            author=current_user,
            title=ad.title,
            text=ad.text,
            created_at=int(time.time() * 1000),
        )
    )
    return {"ok": True, "id": ad_id, "pcoins": acc["pcoins"] - 10}


# ===== П-БАЛЛЫ =====
@app.post("/pcoins/earn")
async def earn_pcoins(current_user: str = Depends(get_current_user)):
    """Начисляет 1 П-Балл текущему пользователю (за посты, без прав мода)."""
    acc = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == current_user)
    )
    if not acc:
        raise HTTPException(404, "Пользователь не найден")
    new_val = acc["pcoins"] + 1
    await database.execute(
        accounts_table.update()
        .where(accounts_table.c.login == current_user)
        .values(pcoins=new_val)
    )
    return {"ok": True, "pcoins": new_val}

@app.post("/pcoins/spend")
@limiter.limit("20/minute")
async def spend_pcoins(request: Request, req: SpendRequest, current_user: str = Depends(get_current_user)):
    """Списывает указанное количество П-Баллов у текущего пользователя."""
    if req.amount <= 0:
        raise HTTPException(400, "Сумма должна быть больше нуля!")
    acc = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == current_user)
    )
    if not acc:
        raise HTTPException(404, "Пользователь не найден")
    if acc["pcoins"] < req.amount:
        raise HTTPException(400, f"Недостаточно П-Баллов! Нужно {req.amount}, у тебя {acc['pcoins']}.")
    new_val = acc["pcoins"] - req.amount
    await database.execute(
        accounts_table.update()
        .where(accounts_table.c.login == current_user)
        .values(pcoins=new_val)
    )
    return {"ok": True, "pcoins": new_val}

@app.post("/pcoins/add")
async def add_pcoins(req: PcoinsUpdate, current_user: str = Depends(get_current_user)):
    await require_admin_or_mod(current_user)
    acc = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == req.login)
    )
    if not acc:
        raise HTTPException(404, "Пользователь не найден")
    new_val = acc["pcoins"] + req.delta
    await database.execute(
        accounts_table.update()
        .where(accounts_table.c.login == req.login)
        .values(pcoins=new_val)
    )
    return {"ok": True, "pcoins": new_val}

@app.get("/pcoins/{login}")
async def get_pcoins(login: str):
    acc = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == login)
    )
    if not acc:
        raise HTTPException(404, "Пользователь не найден")
    return {"pcoins": acc["pcoins"]}


# ===== ОНЛАЙН =====
@app.post("/online/ping")
async def ping_online(req: PingRequest):
    now = int(time.time() * 1000)
    existing = await database.fetch_one(
        online_table.select().where(online_table.c.login == req.login)
    )
    if existing:
        await database.execute(
            online_table.update()
            .where(online_table.c.login == req.login)
            .values(last_seen=now)
        )
    else:
        await database.execute(
            online_table.insert().values(login=req.login, last_seen=now)
        )
    return {"ok": True}

@app.delete("/online/{login}")
async def remove_online(login: str):
    await database.execute(
        online_table.delete().where(online_table.c.login == login)
    )
    return {"ok": True}

@app.get("/online")
async def get_online():
    cutoff = int(time.time() * 1000) - 20000
    rows = await database.fetch_all(
        online_table.select().where(online_table.c.last_seen > cutoff)
    )
    return [r["login"] for r in rows]


# ===== МОДЕРАЦИЯ =====
@app.post("/mod/assign")
async def assign_moderator(req: AssignModRequest, current_user: str = Depends(get_current_user)):
    requester_role = await get_role(current_user)
    if requester_role != "admin":
        raise HTTPException(403, "Только админ может назначать модераторов!")
    target_acc = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == req.target)
    )
    if not target_acc:
        raise HTTPException(404, f"Пользователь '{req.target}' не найден!")
    existing_role = await database.fetch_one(
        roles_table.select().where(roles_table.c.login == req.target)
    )
    if existing_role:
        if existing_role["role"] == "admin":
            raise HTTPException(400, "Нельзя изменить роль другого админа!")
        await database.execute(
            roles_table.update()
            .where(roles_table.c.login == req.target)
            .values(role="moderator")
        )
    else:
        await database.execute(
            roles_table.insert().values(login=req.target, role="moderator")
        )
    return {"ok": True, "message": f"{req.target} теперь модератор!"}

@app.post("/mod/ban")
async def ban_user(req: BanRequest, current_user: str = Depends(get_current_user)):
    requester_role = await require_admin_or_mod(current_user)
    if current_user == req.target:
        raise HTTPException(400, "Нельзя забанить самого себя!")
    target_acc = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == req.target)
    )
    if not target_acc:
        raise HTTPException(404, f"Пользователь '{req.target}' не найден!")
    target_role = await get_role(req.target)
    if target_role in ("admin", "moderator") and requester_role != "admin":
        raise HTTPException(403, "Модератор не может банить других модераторов или админов!")
    if target_role == "admin":
        raise HTTPException(403, "Нельзя забанить админа!")
    await database.execute(accounts_table.delete().where(accounts_table.c.login == req.target))
    await database.execute(roles_table.delete().where(roles_table.c.login == req.target))
    await database.execute(online_table.delete().where(online_table.c.login == req.target))
    await database.execute(timeouts_table.delete().where(timeouts_table.c.login == req.target))
    return {"ok": True, "message": f"{req.target} забанен и удалён!"}

@app.post("/mod/timeout")
async def timeout_user(req: TimeoutRequest, current_user: str = Depends(get_current_user)):
    requester_role = await require_admin_or_mod(current_user)
    if current_user == req.target:
        raise HTTPException(400, "Нельзя дать тайм-аут самому себе!")
    target_acc = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == req.target)
    )
    if not target_acc:
        raise HTTPException(404, f"Пользователь '{req.target}' не найден!")
    target_role = await get_role(req.target)
    if target_role in ("admin", "moderator") and requester_role != "admin":
        raise HTTPException(403, "Модератор не может давать тайм-аут другим модераторам или админам!")
    if target_role == "admin":
        raise HTTPException(403, "Нельзя дать тайм-аут админу!")
    if req.duration_minutes <= 0:
        raise HTTPException(400, "Длительность тайм-аута должна быть больше 0!")
    timeout_until = int(time.time() * 1000) + req.duration_minutes * 60 * 1000
    existing = await database.fetch_one(
        timeouts_table.select().where(timeouts_table.c.login == req.target)
    )
    if existing:
        await database.execute(
            timeouts_table.update()
            .where(timeouts_table.c.login == req.target)
            .values(timeout_until=timeout_until)
        )
    else:
        await database.execute(
            timeouts_table.insert().values(login=req.target, timeout_until=timeout_until)
        )
    return {"ok": True, "message": f"{req.target} получил тайм-аут на {req.duration_minutes} мин.", "timeout_until": timeout_until}

@app.get("/mod/timeout/{login}")
async def check_timeout(login: str):
    timed_out = await is_timed_out(login)
    if timed_out:
        row = await database.fetch_one(
            timeouts_table.select().where(timeouts_table.c.login == login)
        )
        return {"timed_out": True, "timeout_until": row["timeout_until"] if row else None}
    return {"timed_out": False}

@app.get("/mod/list")
async def list_moderators():
    rows = await database.fetch_all(roles_table.select())
    return [{"login": r["login"], "role": r["role"]} for r in rows]

@app.delete("/mod/clear-feed")
async def clear_feed(current_user: str = Depends(get_current_user)):
    requester_role = await get_role(current_user)
    if requester_role != "admin":
        raise HTTPException(403, "Только админ может очистить ленту!")
    await database.execute(comments_table.delete())
    await database.execute(posts_table.delete())
    return {"ok": True, "message": "Лента очищена!"}


# ===== ЗМЕЙКА: ЛИДЕРБОРД =====
class SnakeScoreRequest(BaseModel):
    score: int

@app.post("/snake/score")
async def submit_snake_score(req: SnakeScoreRequest, current_user: str = Depends(get_current_user)):
    if req.score <= 0:
        return {"ok": True, "updated": False}
    existing = await database.fetch_one(
        snake_scores_table.select().where(snake_scores_table.c.login == current_user)
    )
    if existing:
        if req.score > existing["score"]:
            await database.execute(
                snake_scores_table.update()
                .where(snake_scores_table.c.login == current_user)
                .values(score=req.score, updated_at=int(time.time() * 1000))
            )
            return {"ok": True, "updated": True, "best": req.score}
        else:
            return {"ok": True, "updated": False, "best": existing["score"]}
    else:
        await database.execute(
            snake_scores_table.insert().values(
                login=current_user,
                score=req.score,
                updated_at=int(time.time() * 1000),
            )
        )
        return {"ok": True, "updated": True, "best": req.score}

@app.get("/snake/leaderboard")
async def get_snake_leaderboard():
    rows = await database.fetch_all(
        snake_scores_table.select().order_by(snake_scores_table.c.score.desc()).limit(10)
    )
    return [{"name": r["login"], "score": r["score"]} for r in rows]


# ===== МУЗЫКА =====
@app.post("/music")
@limiter.limit("10/minute")
async def publish_music(request: Request, req: MusicTrackCreate, current_user: str = Depends(get_current_user)):
    cost = 3 + (3 if req.has_gif else 0)
    acc = await database.fetch_one(
        accounts_table.select().where(accounts_table.c.login == current_user)
    )
    if not acc:
        raise HTTPException(404, "Пользователь не найден")
    if acc["pcoins"] < cost:
        raise HTTPException(400, f"Недостаточно П-Баллов! Нужно {cost}, у тебя {acc['pcoins']}.")
    new_pcoins = acc["pcoins"] - cost
    await database.execute(
        accounts_table.update()
        .where(accounts_table.c.login == current_user)
        .values(pcoins=new_pcoins)
    )
    import uuid
    track_id = str(int(time.time() * 1000)) + "_" + str(uuid.uuid4()).replace("-", "")[:9]
    from datetime import datetime
    now_str = datetime.now().strftime("%H:%M, %d.%m.%Y")
    await database.execute(
        music_tracks_table.insert().values(
            id=track_id,
            title=req.title,
            artist=req.artist,
            author=current_user,
            time_str=now_str,
            has_gif=req.has_gif,
            audio_data=req.audio_data,
            cover_data=req.cover_data,
            created_at=int(time.time() * 1000),
        )
    )
    return {"ok": True, "id": track_id, "pcoins": new_pcoins}


@app.get("/music")
async def get_music():
    rows = await database.fetch_all(
        music_tracks_table.select()
        .order_by(music_tracks_table.c.created_at.desc())
        .limit(50)
    )
    return [
        {
            "id": r["id"],
            "title": r["title"],
            "artist": r["artist"],
            "author": r["author"],
            "time": r["time_str"],
            "hasGif": r["has_gif"],
            "hasCover": r["cover_data"] is not None,
            "cover_data": r["cover_data"],
        }
        for r in rows
    ]


@app.get("/music/{track_id}/audio")
async def get_music_audio(track_id: str):
    row = await database.fetch_one(
        music_tracks_table.select().where(music_tracks_table.c.id == track_id)
    )
    if not row or not row["audio_data"]:
        raise HTTPException(404, "Аудио не найдено")
    return {"audio_data": row["audio_data"]}

