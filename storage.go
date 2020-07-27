package revocation

import (
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
)

const schema = `
  CREATE TABLE IF NOT EXISTS tree (
    internal_id INTEGER NOT NULL PRIMARY KEY,
    leaf_id INTEGER,
    data VARBINARY(255) NOT NULL,
    leftchild INTEGER,
    rightchild INTEGER
    );
`

const schema2 = `
  CREATE TABLE IF NOT EXISTS info (
    height INTEGER
    );
`

const insertNode = `INSERT INTO tree(internal_id,leaf_id,data,leftchild,rightchild) VALUES (?,?,?,?,?);`
const insertHeight = `INSERT INTO info(height) VALUES (?);`
const selectRootData = `SELECT data FROM tree WHERE internal_id = 0;`
const selectAllRows = `SELECT * FROM tree;`
const selectHeight = `SELECT height FROM info;`

type Storage struct {
	db             *sql.DB
	insertNode     *sql.Stmt
  insertHeight *sql.Stmt
	selectRootData *sql.Stmt
	selectAllRows  *sql.Stmt
	selectHeight   *sql.Stmt
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

// Open opens the underlying persistent data store.
// Should be called before attempting to use any of the store or search methods.
func (s *Storage) Open(dbPath string) error {
	var err error
	if s.db != nil {
		return errors.New("attempting to call Open() on an already Open()'d Storage")
	}
	if len(dbPath) == 0 {
		return errors.New("attempting to call Open() with an empty file name")
	}
	s.db, err = sql.Open("mysql", dbPath)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
  if _, err := s.db.Exec(schema2); err != nil {
    return err
  }
	for _, p := range []statementSQLPair{
		{&s.insertNode, insertNode},
    {&s.insertHeight, insertHeight},
		{&s.selectRootData, selectRootData},
		{&s.selectAllRows, selectAllRows},
		{&s.selectHeight, selectHeight}} {
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

func (s *Storage) GetNodes() ([]Node, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	nodes, err := s.getNodes(tx)
	if err != nil {
		return nil, err
	}
	return nodes, nil
}

func (s *Storage) getNodes(tx *sql.Tx) ([]Node, error) {
	stmt := tx.Stmt(s.selectAllRows)
	r, err := stmt.Query()
	if err != nil {
		return nil, err
	}
	var nodes []Node
	for r.Next() {
		n := Node{}
		err = r.Scan(&n.Internal_id, &n.Leaf_id, &n.Data, &n.Left, &n.Right)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

func (s *Storage) GetMTH() ([]byte, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	var mth []byte
	if mth, err = s.getMTH(tx); err != nil {
		return nil, err
	}
	return mth, nil
}

func (s *Storage) getMTH(tx *sql.Tx) ([]byte, error) {
	stmt := tx.Stmt(s.selectRootData)
	r, err := stmt.Query()
	if err != nil {
		return nil, err
	}
	if !r.Next() {
		return nil, fmt.Errorf("empty scan returned while querying %v", stmt)
	}
	var mth []byte
	if err := r.Scan(&mth); err != nil {
		return nil, err
	}
	return mth, nil
}

func (s *Storage) GetHeight() (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	var height int
	if height, err = s.getHeight(tx); err != nil {
		return 0, err
	}
	return height, nil
}

func (s *Storage) getHeight(tx *sql.Tx) (int, error) {
	stmt := tx.Stmt(s.selectHeight)
	r, err := stmt.Query()
	if err != nil {
		return 0, err
	}
	if !r.Next() {
		return 0, fmt.Errorf("empty scan returned while querying %v", stmt)
	}
	var height int
	if err := r.Scan(&height); err != nil {
		return 0, err
	}
	return height, nil
}

func (s *Storage) SetHeight(h int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	// If we return a non-nil error, then rollback the transaction.
	defer func() {
		if err != nil {
			tx.Rollback()
		}
		err = tx.Commit()
	}()

	if err := s.setHeight(tx, h); err != nil {
		return err
	}
	return nil
}

func (s *Storage) setHeight(tx *sql.Tx, h int) error {
	stmt := tx.Stmt(s.insertHeight)
	_, err := stmt.Exec(h)
	if err != nil {
		return err
	}
	return nil
}

func (s *Storage) AddNode(n Node) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	// If we return a non-nil error, then rollback the transaction.
	defer func() {
		if err != nil {
			tx.Rollback()
		}
		err = tx.Commit()
	}()

	if err := s.addNode(tx, n); err != nil {
		return err
	}
	return nil
}

func (s *Storage) addNode(tx *sql.Tx, n Node) error {
	stmt := tx.Stmt(s.insertNode)
	_, err := stmt.Exec(n.Internal_id, n.Leaf_id, n.Data, n.Left, n.Right)
	if err != nil {
		return err
	}
	return nil
}
