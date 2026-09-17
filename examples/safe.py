def find_user(cursor, user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return cursor.execute(query, (user_id,))
