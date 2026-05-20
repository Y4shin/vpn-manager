package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

type Store struct {
	DB *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{DB: db}, nil
}

func (s *Store) Close() error { return s.DB.Close() }

type User struct {
	ID          int64
	OIDCSub     string
	Email       string
	Groups      []string
	CreatedAt   time.Time
	LastLoginAt time.Time
}

type Device struct {
	ID              int64
	UserID          int64
	Name            string
	PublicKey       string
	IP              string
	GroupAtCreation string
	CreatedAt       time.Time
	LastHandshakeAt *time.Time
}

func (s *Store) UpsertUser(ctx context.Context, sub, email string, groups []string) (*User, error) {
	groupsJSON, err := json.Marshal(groups)
	if err != nil {
		return nil, err
	}
	_, err = s.DB.ExecContext(ctx, `
        INSERT INTO users (oidc_sub, email, groups_json, last_login_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(oidc_sub) DO UPDATE SET
            email = excluded.email,
            groups_json = excluded.groups_json,
            last_login_at = CURRENT_TIMESTAMP
    `, sub, email, string(groupsJSON))
	if err != nil {
		return nil, fmt.Errorf("upsert user: %w", err)
	}
	return s.GetUserBySub(ctx, sub)
}

func (s *Store) GetUserBySub(ctx context.Context, sub string) (*User, error) {
	row := s.DB.QueryRowContext(ctx, `
        SELECT id, oidc_sub, email, groups_json, created_at, last_login_at
        FROM users WHERE oidc_sub = ?
    `, sub)
	return scanUser(row)
}

func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	row := s.DB.QueryRowContext(ctx, `
        SELECT id, oidc_sub, email, groups_json, created_at, last_login_at
        FROM users WHERE id = ?
    `, id)
	return scanUser(row)
}

func scanUser(row *sql.Row) (*User, error) {
	var u User
	var groupsJSON string
	if err := row.Scan(&u.ID, &u.OIDCSub, &u.Email, &groupsJSON, &u.CreatedAt, &u.LastLoginAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(groupsJSON), &u.Groups); err != nil {
		return nil, fmt.Errorf("unmarshal groups: %w", err)
	}
	return &u, nil
}

func (s *Store) CreateDevice(ctx context.Context, d *Device) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `
        INSERT INTO devices (user_id, name, public_key, ip, group_at_creation)
        VALUES (?, ?, ?, ?, ?)
    `, d.UserID, d.Name, d.PublicKey, d.IP, d.GroupAtCreation)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteDevice(ctx context.Context, userID, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM devices WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListDevicesByUser(ctx context.Context, userID int64) ([]Device, error) {
	rows, err := s.DB.QueryContext(ctx, `
        SELECT id, user_id, name, public_key, ip, group_at_creation, created_at, last_handshake_at
        FROM devices WHERE user_id = ? ORDER BY created_at DESC
    `, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDevices(rows)
}

func (s *Store) ListAllDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.DB.QueryContext(ctx, `
        SELECT id, user_id, name, public_key, ip, group_at_creation, created_at, last_handshake_at
        FROM devices
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDevices(rows)
}

func scanDevices(rows *sql.Rows) ([]Device, error) {
	var out []Device
	for rows.Next() {
		var d Device
		var hs sql.NullTime
		if err := rows.Scan(&d.ID, &d.UserID, &d.Name, &d.PublicKey, &d.IP, &d.GroupAtCreation, &d.CreatedAt, &hs); err != nil {
			return nil, err
		}
		if hs.Valid {
			t := hs.Time
			d.LastHandshakeAt = &t
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) UpdateHandshake(ctx context.Context, publicKey string, t time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE devices SET last_handshake_at = ? WHERE public_key = ?`, t, publicKey)
	return err
}

func (s *Store) UsedIPs(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT ip FROM devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := make(map[string]struct{})
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		used[ip] = struct{}{}
	}
	return used, rows.Err()
}
