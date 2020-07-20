package revocation

import (
  "fmt"
  "log"
  "database/sql"
  dr "github.com/go-sql-driver/mysql"
)

const schema = `
  CREATE TABLE IF NOT EXISTS entries (
    value CHAR(20) NOT NULL,
    location INTEGER NOT NULL PRIMARY KEY
    );

  CREATE TABLE IF NOT EXISTS PowersOfTwo (
    exponent INTEGER NOT NULL PRIMARY KEY CHECK(exponent >= 0),
    pwr_two INTEGER NOT NULL UNIQUE CHECK(pwr_two>=1)
    );

  INSERT INTO PowersOfTwo
  VALUES (0, 1), (1, 2), (2, 4), (3, 8),
       (4, 16), (5, 32), (6, 64), (7, 128),
       (8, 256);

  `

const insertEntry = `INSERT INTO entries(value, location) VALUES ($1, $2);`
const selectEntryValue = `SELECT location FROM entries WHERE value = $1;`


type Storage struct {
  db *sql.DB
  insertEntry *sql.Stmt
  selectEntryID *sql.Stmt
}

type statementSQLPair struct {
	Statement **sql.Stmt
	SQL       string
}

func prepareStatement(db *sql.DB, s statementSQLPair) error {
	stmt, err := db.Prepare(s.SQL)
	if err != nil {
		return err
	}
	*(s.Statement) = stmt
	return nil
}


// Opens mysql database
func (s *Storage) Open(creds string) error {
	var err error
	if s.db != nil {
		return errors.New("attempting to call Open() on an already Open()'d Storage")
	}
	if len(dbPath) == 0 {
		return errors.New("attempting to call Open() with an empty file name")
	}
	s.db, err = sql.Open("mysql", creds)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	for _, p := range []statementSQLPair{
		{&s.insertEntry, insertEntry},
		{&s.selectEntryValue, selectEntryValue}} {
    if err := prepareStatement(s.db, p); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the underlying DB storage.
func (s *Storage) Close() error {
	return s.db.Close()
}

func (s *Storage) AddEntry(tx *sql.Tx, value string, location int) error {
  stmt := tx.Stmt(s.insertEntry)
  _, err := stmt.Exec(value,location)
  if err != nil {
    return err
  }
  return nil
}

func (s *Storage) GetEntry(tx *sql.Tx, value string) (int, error) {
  stmt := tx.Stmt(s.selectEntryID)
  r, err := stmt.Query(value)
  if err != nil {
    return -1, err
  }
  if !rows.Next() {
	  return -1, fmt.Errorf("not revoked")
	}
	var location int
	if err = rows.Scan(&location); err != nil {
	  return -1, err
	}
	return id, nil
}
