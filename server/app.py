#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")
        image_url = data.get("image_url")
        bio = data.get("bio")

        errors = []

     
        if not username:
            errors.append("Username is required.")
        if not password or len(password) < 6:
            errors.append("Password must be at least 6 characters long.")

        if errors:
            return {"errors": errors}, 422

        try:
          
            user = User(
                username=username,
                image_url=image_url,
                bio=bio,
            )
            user.password_hash = password  
            db.session.add(user)
            db.session.commit()

            # Save user_id in session
            session["user_id"] = user.id

            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 201

        except Exception as e:
            # Catch things like duplicate username constraint
            db.session.rollback()
            return {"errors": [str(e)]}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.get(user_id)

        if not user:
            return {"error": "Unauthorized"}, 401

        return {
            "id": user.id,
            "username": user.username,
            "image_url": user.image_url,
            "bio": user.bio
        }, 200

class Login(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            # Save user_id in session
            session["user_id"] = user.id

            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 200

        return {"error": "Invalid username or password"}, 401

class Logout(Resource):
    def delete(self):
        # check if logged in
        if session.get("user_id"):
            session.pop("user_id", None)  # remove user_id from session
            return {}, 204  # ✅ empty response, 204 No Content
        else:
            return {"error": "Unauthorized"}, 401


class RecipeIndex(Resource):
    def get(self):
        # Check if logged in
        if not session.get("user_id"):
            return {"error": "Unauthorized"}, 401

        # Get all recipes, including nested user
        recipes = Recipe.query.all()

        # Serialize each recipe with nested user data
        recipe_list = []
        for recipe in recipes:
            recipe_list.append({
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username,
                    "image_url": recipe.user.image_url,
                    "bio": recipe.user.bio,
                }
            })

        return recipe_list, 200

    def post(self):
        # Check if logged in
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()

        try:
            new_recipe = Recipe(
                title=data.get("title"),
                instructions=data.get("instructions"),
                minutes_to_complete=data.get("minutes_to_complete"),
                user_id=user_id
            )

            db.session.add(new_recipe)
            db.session.commit()

            recipe_data = {
                "id": new_recipe.id,
                "title": new_recipe.title,
                "instructions": new_recipe.instructions,
                "minutes_to_complete": new_recipe.minutes_to_complete,
                "user": {
                    "id": new_recipe.user.id,
                    "username": new_recipe.user.username,
                    "image_url": new_recipe.user.image_url,
                    "bio": new_recipe.user.bio,
                }
            }

            return recipe_data, 201

        except ValueError as e:
            # Catch validation errors (like short instructions)
            return {"errors": [str(e)]}, 422
        except IntegrityError:
            db.session.rollback()
            return {"errors": ["Invalid recipe data"]}, 422

    

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)