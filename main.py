from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
import mysql.connector
import bcrypt
import jwt
from typing import Optional, List


SECRET_KEY = "my_secret_key"


app = FastAPI()


def get_db():
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password=""
    )
    return db


def create_database():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS novel_db")
    db.close()

def create_tables():
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS novels (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            content TEXT,
            user_id INT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS likes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            novel_id INT,
            user_id INT,
            FOREIGN KEY (novel_id) REFERENCES novels(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            novel_id INT,
            user_id INT,
            text TEXT,
            FOREIGN KEY (novel_id) REFERENCES novels(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS wishlists (
            id INT AUTO_INCREMENT PRIMARY KEY,
            novel_id INT,
            user_id INT,
            FOREIGN KEY (novel_id) REFERENCES novels(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    db.commit()
    db.close()

@app.on_event("startup")
def on_startup():
    create_database()
    create_tables()

class UserCreate(BaseModel):
    username: str
    password: str
    email: str

class UserLogin(BaseModel):
    username: str
    password: str

class NovelCreate(BaseModel):
    title: str
    description: str
    content: str

class CommentCreate(BaseModel):
    novel_id: int
    text: str

class LikeCreate(BaseModel):
    novel_id: int

class WishListCreate(BaseModel):
    novel_id: int

class NovelUpdate(BaseModel):
    title: Optional[str]
    description: Optional[str]
    content: Optional[str]

class ProfileUpdate(BaseModel):
    username: Optional[str]
    email: Optional[str]
    password: Optional[str]


def create_user_token(user_id: int):
    token = jwt.encode({"user_id": user_id}, SECRET_KEY, algorithm="HS256")
    return token

def verify_token(token: Optional[str]):
    if token is None:
        raise HTTPException(status_code=401, detail="Token is required")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/users/")
def create_user(user: UserCreate):
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor()

  
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())


    cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", 
                   (user.username, user.email, hashed_password))
    db.commit()
    db.close()

    return {"msg": "User created successfully"}


@app.post("/login/")
def login_user(user: UserLogin):
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor(dictionary=True)
   
    cursor.execute("SELECT * FROM users WHERE username = %s", (user.username,))
    db_user = cursor.fetchone()

   
    if db_user and bcrypt.checkpw(user.password.encode('utf-8'), db_user['password'].encode('utf-8')):
        token = create_user_token(db_user['id'])
        db.close()
        return {"token": token}
    
    db.close()
    raise HTTPException(status_code=400, detail="Invalid credentials")


@app.post("/novels/")
def upload_novel(novel: NovelCreate, token: Optional[str] = None):
    user_id = verify_token(token)

    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor()

    cursor.execute("INSERT INTO novels (title, description, content, user_id) VALUES (%s, %s, %s, %s)", 
                   (novel.title, novel.description, novel.content, user_id))
    db.commit()
    db.close()

    return {"msg": "Novel uploaded successfully"}


@app.post("/novels/like/")
def like_novel(like: LikeCreate, token: Optional[str] = None):
    user_id = verify_token(token)

    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor()

  
    cursor.execute("INSERT INTO likes (novel_id, user_id) VALUES (%s, %s)", 
                   (like.novel_id, user_id))
    db.commit()
    db.close()

    return {"msg": "Liked the novel"}

@app.post("/novels/comment/")
def comment_novel(comment: CommentCreate, token: Optional[str] = None):
    user_id = verify_token(token)

    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor()

    cursor.execute("INSERT INTO comments (novel_id, user_id, text) VALUES (%s, %s, %s)", 
                   (comment.novel_id, user_id, comment.text))
    db.commit()
    db.close()

    return {"msg": "Comment added"}

@app.post("/wishlist/")
def add_to_wishlist(wishlist: WishListCreate, token: Optional[str] = None):
    user_id = verify_token(token)

    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor()

 
    cursor.execute("INSERT INTO wishlists (novel_id, user_id) VALUES (%s, %s)", 
                   (wishlist.novel_id, user_id))
    db.commit()
    db.close()

    return {"msg": "Added to wishlist"}


@app.get("/novels/{novel_id}/download/")
def download_novel(novel_id: int):
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM novels WHERE id = %s", (novel_id,))
    novel = cursor.fetchone()
    db.close()

    if not novel:
        raise HTTPException(status_code=404, detail="Novel not found")

    return novel


@app.put("/novels/{novel_id}/")
def update_novel(novel_id: int, novel: NovelUpdate, token: Optional[str] = None):
    user_id = verify_token(token)

    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor()

    
    query = "UPDATE novels SET title = %s, description = %s, content = %s WHERE id = %s AND user_id = %s"
    cursor.execute(query, (novel.title, novel.description, novel.content, novel_id, user_id))
    db.commit()
    db.close()

    return {"msg": "Novel updated successfully"}


@app.delete("/novels/{novel_id}/")
def delete_novel(novel_id: int, token: Optional[str] = None):
    user_id = verify_token(token)

    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor()

    cursor.execute("DELETE FROM novels WHERE id = %s AND user_id = %s", (novel_id, user_id))
    db.commit()
    db.close()

    return {"msg": "Novel deleted successfully"}

@app.get("/users/{user_id}/novels/")
def get_user_novels(user_id: int):
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor(dictionary=True)

   
    cursor.execute("SELECT * FROM novels WHERE user_id = %s", (user_id,))
    novels = cursor.fetchall()
    db.close()

    return novels

@app.get("/novels/")
def get_all_novels():
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor(dictionary=True)


    cursor.execute("SELECT * FROM novels")
    novels = cursor.fetchall()
    db.close()

    return novels

@app.get("/novels/{novel_id}/")
def get_novel_details(novel_id: int):
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor(dictionary=True)

  
    cursor.execute("SELECT * FROM novels WHERE id = %s", (novel_id,))
    novel = cursor.fetchone()
    db.close()

    if not novel:
        raise HTTPException(status_code=404, detail="Novel not found")

    return novel


@app.put("/users/profile/")
def update_profile(profile: ProfileUpdate, token: Optional[str] = None):
    user_id = verify_token(token)

    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor()


    query = "UPDATE users SET username = %s, email = %s, password = %s WHERE id = %s"
    cursor.execute(query, (profile.username, profile.email, profile.password, user_id))
    db.commit()
    db.close()

    return {"msg": "Profile updated successfully"}

@app.delete("/users/")
def delete_user(token: Optional[str] = None):
    user_id = verify_token(token)

    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor()

  
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    db.commit()
    db.close()

    return {"msg": "User deleted"}


@app.get("/users/{user_id}/")
def get_user_details(user_id: int):
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor(dictionary=True)

   
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    db.close()

    return user


@app.get("/novels/{novel_id}/likes/")
def get_novel_likes(novel_id: int):
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor(dictionary=True)

  
    cursor.execute("SELECT COUNT(*) AS likes FROM likes WHERE novel_id = %s", (novel_id,))
    likes = cursor.fetchone()
    db.close()

    return likes

@app.get("/novels/{novel_id}/comments/")
def get_novel_comments(novel_id: int):
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor(dictionary=True)


    cursor.execute("SELECT * FROM comments WHERE novel_id = %s", (novel_id,))
    comments = cursor.fetchall()
    db.close()

    return comments


@app.get("/users/{user_id}/wishlist/")
def get_user_wishlist(user_id: int):
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor(dictionary=True)

  
    cursor.execute("SELECT novels.* FROM wishlists JOIN novels ON wishlists.novel_id = novels.id WHERE wishlists.user_id = %s", (user_id,))
    wishlist = cursor.fetchall()
    db.close()

    return wishlist


@app.delete("/wishlist/{novel_id}/")
def remove_from_wishlist(novel_id: int, token: Optional[str] = None):
    user_id = verify_token(token)

    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor()


    cursor.execute("DELETE FROM wishlists WHERE novel_id = %s AND user_id = %s", (novel_id, user_id))
    db.commit()
    db.close()

    return {"msg": "Novel removed from wishlist"}


@app.get("/novels/search/")
def search_novels(title: str):
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="novel_db"
    )
    cursor = db.cursor(dictionary=True)


    query = "SELECT * FROM novels WHERE title LIKE %s"
    cursor.execute(query, ('%' + title + '%',))
    novels = cursor.fetchall()
    db.close()

    return novels
