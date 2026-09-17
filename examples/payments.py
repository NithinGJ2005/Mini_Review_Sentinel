def find_user(cursor, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)
