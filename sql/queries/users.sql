-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: ResetUsers :exec
DELETE FROM users;

-- name: GetUserPasswordByEmail :one
SELECT hashed_password
FROM users
WHERE email = $1;

-- name: GetUserByEmail :one
SELECT id, created_at, updated_at, email, is_chirpy_red
FROM users
WHERE email = $1;

-- name: UpdateEmailAndPassword :one
UPDATE users
SET email = $1, hashed_password = $2, updated_at = NOW()
WHERE id = $3
RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: UpdateChirpyRedStatus :exec
UPDATE users
SET is_chirpy_red = true, updated_at = NOW()
WHERE id = $1;