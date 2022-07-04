import database as _database
import models as _models
import fastapi.security as _security
import sqlalchemy.orm as _orm
import schemas as _schemas
import email_validator as _email_validator
import fastapi as _fastapi
import passlib.hash as _hash
import jwt as _jwt

_JWT_SECRET = "chdcbdjwbcjdw"
oauth2schema = _security.OAuth2PasswordBearer("/api/v1/login")

def create_db():
    return _database.Base.metadata.create_all(bind=_database.engine)


def get_db():
    db = _database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def getUserByEmail(email: str, db: _orm.Session):
    return db.query(_models.UserModel).filter(_models.UserModel.email == email).first()


async def create_user(user: _schemas.UserRequest, db: _orm.Session):
    # check for valid email
    try:
        isValid = _email_validator.validate_email(email=user.email)
        email = isValid.email
    except _email_validator.EmailNotValidError:
        raise _fastapi.HTTPException(status_code=400, detail="Provide Valid Email ID")
    # convert password to hash form
    hashed_password = _hash.bcrypt.hash(user.password)
    # save user in database
    user_obj = _models.UserModel(
        email=email,
        name=user.name,
        phone=user.phone,
        password_hash=hashed_password
    )
    # save user in db
    db.add(user_obj)
    db.commit()
    db.refesh(user_obj)
    return user_obj


async def create_token(user: _models.UserModel):
    # convert user model to schema
    user_schema = _schemas.UserResponse.from_orm(user)
    # convert object to dictionary
    user_dict = user_schema.dict()
    del user_dict["created_at"]

    token = _jwt.encode(user_dict, _JWT_SECRET)

    return dict(access_token=token, token_type="bearer")

async def login(email: str, password: str, db: _orm.Session):
    db_user = await getUserByEmail(email=email, db=db)
    # return false if no user with email found
    if not db_user:
        return False
    # return false if no user with password found
    if not db_user.password_verification(password=password):
        return False

    return db_user

async def current_user(db: _orm.Session = _fastapi.Depends(get_db),
                       token: str = _fastapi.Depends(oauth2schema)):
    try:
        payload = _jwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
        # get user via ID
        db_user = db.query(_models.userModel).get(payload["id"])
    except:
        raise _fastapi.HTTPException(status=401, detail="Wrong Login Details")

    # if login details are good
    return _schemas.UserResponse.from_orm(db_user)

async def create_post(user: _schemas.UserResponse, db: _orm.Session,
                      post: _schemas.PostRequest):
    post = _models.PostModel(**post.dict(), user_id=user.id)
    db.add(post)
    db.commit()
    db.refresh(post)

    return _schemas.PostResponse.from_orm(post)

async def get_posts_by_user(user: _schemas.UserResponse, db: _orm.Session):
    posts = db.query(_models.PostModel).filter_by(user_id=user.id)
    # convert each post model to post schema and return list
    return list(map(_schemas.PostResponse.from_orm, posts))

async def get_posts_by_all(db: _orm.Session):
    posts = db.query(_models.PostModel)
    # convert each post model to post schema and return list
    return list(map(_schemas.PostResponse.from_orm, posts))

async def get_post_detail(post_id: int, db: _orm.Session):
    db_post = db.query(_models.PostModel).filer(_models.PostModel.id==post_id).first()
    if db_post is None:
        raise _fastapi.HTTPException(status_code=404, detail="Post not found")
    # return _schemas.PostResponse.from_orm(db_post)
    return db_post

async def get_user_detail(user_id: int, db: _orm.Session):
    db_user = db.query(_models.UserModel).filer(_models.UserModel.id==user_id).first()
    if db_user is None:
        raise _fastapi.HTTPException(status_code=404, detail="User not found")
    return _schemas.UserResponse.from_orm(db_user)
    # return db_post

async def delete_post(post: _models.PostModel, db: _orm.Session):
    db.delete(post)
    db.commit()

async def update_post(
        post_request: _schemas.PostRequest,
        post: _models.PostModel,
        db: _orm.Session
):
    post.post_title = post_request.post_title
    post.post_description = post_request.post_description
    post.image = post_request.image

    db.commit()
    db.refresh(post)

    return _schemas.PostResponse.from_orm(post)