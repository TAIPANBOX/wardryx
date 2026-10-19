package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Finding F-023, the part #121 left open: keys were stored under their digest,
// but authenticate still indexed the store with the presented bearer's digest,
// a hash-table lookup whose work depends on the bytes it hashes. The comparison
// is now a walk over every configured digest with crypto/subtle and no early
// exit (CLAUDE.md invariant 42). A timing difference is not observable from a
// test, so this one reads the syntax of authenticate, the way the approval
// verifier's constant-time test does.

// authenticateBody returns the body of (*Server).authenticate from the
// package's non-test sources.
func authenticateBody(t *testing.T) *ast.BlockStmt {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing the package: %v", err)
	}
	pkg, ok := pkgs["api"]
	if !ok {
		t.Fatal("package api not found: this measured nothing")
	}
	for _, f := range pkg.Files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if ok && fd.Recv != nil && fd.Name.Name == "authenticate" {
				return fd.Body
			}
		}
	}
	t.Fatal("(*Server).authenticate not found: this measured nothing")
	return nil
}

// isKeysSelector reports whether e is the store field s.keys.
func isKeysSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "keys" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "s"
}

func TestTheBearerIsComparedInConstantTime(t *testing.T) {
	body := authenticateBody(t)

	// No index of the key store anywhere in authenticate: a lookup by the
	// digest is the shape #121 kept.
	ast.Inspect(body, func(n ast.Node) bool {
		if ix, ok := n.(*ast.IndexExpr); ok && isKeysSelector(ix.X) {
			t.Errorf("authenticate indexes the key store (s.keys[...]) at %v: "+
				"a hash lookup by the presented digest is not a constant-time comparison", ix.Pos())
		}
		return true
	})

	// The store is walked, with every configured digest compared.
	var ranges []*ast.RangeStmt
	ast.Inspect(body, func(n ast.Node) bool {
		if rs, ok := n.(*ast.RangeStmt); ok && isKeysSelector(rs.X) {
			ranges = append(ranges, rs)
		}
		return true
	})
	if len(ranges) != 1 {
		t.Fatalf("authenticate ranges over the key store %d times, want exactly 1: "+
			"every configured digest must be compared", len(ranges))
	}
	loop := ranges[0]

	// The comparison must decide the match: subtle.ConstantTimeCompare is the
	// condition of an if in the walk, not a call whose result is ignored.
	compared := false
	ast.Inspect(loop.Body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		ast.Inspect(ifs.Cond, func(c ast.Node) bool {
			call, ok := c.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ConstantTimeCompare" {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "subtle" {
					compared = true
				}
			}
			return true
		})
		return true
	})
	ast.Inspect(loop.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BranchStmt:
			t.Errorf("the key walk has a %s at %v: no early exit is allowed, "+
				"every configured digest is compared", x.Tok, x.Pos())
		case *ast.ReturnStmt:
			t.Errorf("the key walk returns at %v: no early exit is allowed, "+
				"every configured digest is compared", x.Pos())
		}
		return true
	})
	if !compared {
		t.Error("the key walk does not decide the match with subtle.ConstantTimeCompare")
	}
}
