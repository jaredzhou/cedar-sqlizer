package sqlizer

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/eval"
	"github.com/jaredzhou/cedar-sqlizer/utils"
	"github.com/lib/pq"
)

var (
	sqlTrue  = "1 = 1"
	sqlFalse = "1 = 0"
)

var (
	Debug = false
)

var ErrInvalidFieldName = errors.New("invalid field name")

type FieldMapper interface {
	Map(name string) (string, error)
}

var DefaultFieldMapper = defaultFieldMapper{}

type defaultFieldMapper struct{}

func (m defaultFieldMapper) Map(name string) (string, error) {
	return name, nil
}

// Sqlizer interface defines the contract for SQL expression builders
type Sqlizer interface {
	ToSql() (string, []interface{}, error)
}

// expr represents a SQL expression template with parameterized placeholders.
// It provides a flexible way to build SQL expressions by combining SQL templates
// with dynamic arguments that can be either Go values or other Sqlizer implementations.
//
// Design:
// - sql: A SQL template string using "?" as placeholders for parameters
// - args: A slice of arguments that can be:
//   - Go values (string, int, bool, etc.) - will be used as-is in the final SQL
//   - Sqlizer implementations - will be expanded and their SQL/args merged
//
// Usage Examples:
//
//	// Simple value substitution
//	Expr("name = ?", "john")                    // "name = ?" with args ["john"]
//	Expr("age > ? AND status = ?", 25, "active") // "age > ? AND status = ?" with args [25, "active"]
//
//	// Nested Sqlizer expansion
//	subExpr := Expr("status = ?", "active")
//	Expr("name = ? AND ?", "john", subExpr)     // "name = ? AND status = ?" with args ["john", "active"]
//
//	// Complex nested expressions
//	innerExpr := Expr("age > ?", 18)
//	Expr("(? OR ?) AND ?",
//	     Expr("name = ?", "john"),
//	     Expr("name = ?", "jane"),
//	     innerExpr)
//
// Placeholder Rules:
// - Use "?" for parameter placeholders
// - Use "??" to escape a literal "?" character in the SQL
// - Arguments are substituted in order of appearance
// - Sqlizer arguments are expanded and their placeholders are merged
type expr struct {
	sql  string
	args []interface{}
}

// Expr creates a new SQL expression with the given template and arguments.
//
// Parameters:
//   - sql: SQL template string with "?" placeholders
//   - args: Variable number of arguments (Go values or Sqlizer implementations)
//
// Returns:
//   - A Sqlizer implementation that can be used in other expressions or converted to SQL
//
// The function supports both simple value substitution and complex nested expression
// expansion, making it a powerful building block for dynamic SQL generation.
//
// Panics:
//   - If the number of arguments doesn't match the number of placeholders in the SQL template
//   - This validation helps catch common errors early and provides clear error messages
func Expr(sql string, args ...interface{}) Sqlizer {
	expectedCount := countPlaceholders(sql)
	if len(args) != expectedCount {
		panic(fmt.Sprintf("Expr: expected %d arguments, got %d for SQL template: %s", expectedCount, len(args), sql))
	}
	return expr{sql: sql, args: args}
}

func (e expr) ToSql() (sql string, args []interface{}, err error) {
	simple := true
	for _, arg := range e.args {
		if _, ok := arg.(Sqlizer); ok {
			simple = false
		}
	}
	if simple {
		// Even for simple cases, we need to handle escaped question marks
		return e.processEscapedSQL(e.sql), e.args, nil
	}

	buf := &bytes.Buffer{}
	ap := e.args
	sp := e.sql

	var isql string
	var iargs []interface{}

	for err == nil && len(ap) > 0 && len(sp) > 0 {
		i := strings.Index(sp, "?")
		if i < 0 {
			// no more placeholders
			break
		}
		if len(sp) > i+1 && sp[i+1:i+2] == "?" {
			// escaped "??"; append single "?" and step past both
			buf.WriteString(sp[:i])
			buf.WriteString("?")
			sp = sp[i+2:]
			continue
		}

		if as, ok := ap[0].(Sqlizer); ok {
			// sqlizer argument; expand it and append the result
			isql, iargs, err = as.ToSql()
			buf.WriteString(sp[:i])
			buf.WriteString(isql)
			args = append(args, iargs...)
		} else {
			// normal argument; append it and the placeholder
			buf.WriteString(sp[:i+1])
			args = append(args, ap[0])
		}

		// step past the argument and placeholder
		ap = ap[1:]
		sp = sp[i+1:]
	}

	// append the remaining sql and arguments
	buf.WriteString(sp)
	return buf.String(), append(args, ap...), err
}

// processEscapedSQL handles escaped question marks in simple cases
func (e expr) processEscapedSQL(sql string) string {
	return strings.ReplaceAll(sql, "??", "?")
}

// countPlaceholders counts the number of parameter placeholders in a SQL template
// It correctly handles escaped question marks (??) by ignoring them
func countPlaceholders(sql string) int {
	count := 0
	for i := 0; i < len(sql); i++ {
		if sql[i] == '?' {
			if i+1 < len(sql) && sql[i+1] == '?' {
				// Skip escaped question mark
				i++
				continue
			}
			count++
		}
	}
	return count
}

type part struct {
	pred interface{}
	args []interface{}
}

func newPart(pred interface{}, args ...interface{}) part {
	return part{pred: pred, args: args}
}

func (p part) ToSql() (sql string, args []interface{}, err error) {
	switch pred := p.pred.(type) {
	case nil:
		// no-op
	case Sqlizer:
		sql, args, err = Sqlizer(pred).ToSql()
	case string:
		sql = pred
		args = p.args
	default:
		err = fmt.Errorf("expected string or Sqlizer, not %T", pred)
	}
	return
}

type concatExpr []interface{}

func (ce concatExpr) ToSql() (sql string, args []interface{}, err error) {
	for _, part := range ce {
		switch p := part.(type) {
		case string:
			sql += p
		case cedar.String:
			sql += string(p)
		case Sqlizer:
			pSql, pArgs, err := p.ToSql()
			if err != nil {
				return "", nil, err
			}
			sql += pSql
			args = append(args, pArgs...)
		default:
			return "", nil, fmt.Errorf("%#v is not a string or Sqlizer: %T", part, part)
		}
	}
	return
}
func ConcatExpr(parts ...interface{}) concatExpr {
	return concatExpr(parts)
}

type conj struct {
	parts       []Sqlizer
	sep         string
	defaultExpr string
}

func (c conj) ToSql() (sql string, args []interface{}, err error) {
	if len(c.parts) == 0 {
		return c.defaultExpr, []interface{}{}, nil
	}
	var sqlParts []string
	for _, sqlizer := range c.parts {
		partSQL, partArgs, err := sqlizer.ToSql()
		if err != nil {
			return "", nil, err
		}
		if partSQL != "" {
			sqlParts = append(sqlParts, partSQL)
			args = append(args, partArgs...)
		}
	}
	if len(sqlParts) > 0 {
		if c.sep == AndSep {
			sql = strings.Join(sqlParts, c.sep)
		} else {
			sql = fmt.Sprintf("(%s)", strings.Join(sqlParts, c.sep))
		}
	}
	return
}

const AndSep = " AND "

func AndExpr(parts ...Sqlizer) Sqlizer {
	return conj{parts: parts, sep: AndSep, defaultExpr: sqlTrue}
}

const OrSep = " OR "

func OrExpr(parts ...Sqlizer) Sqlizer {
	return conj{parts: parts, sep: OrSep, defaultExpr: sqlFalse}
}

func ToSql(node ast.IsNode, env eval.Env, mapper FieldMapper) (sql string, args []interface{}, err error) {
	result, err := toSqlOrValue(node, env, mapper)
	if err != nil {
		return "", nil, err
	}
	if result.isValue {
		val, err := utils.ValueToType[cedar.Boolean](result.value)
		if err != nil {
			return "", nil, err
		}
		if val {
			return sqlTrue, nil, nil
		}
		return sqlFalse, nil, nil
	}
	return result.ToSql()
}

type result struct {
	isValue bool
	value   cedar.Value
	sqlizer Sqlizer
}

func valueToResult(isValue bool, value cedar.Value, sqlizer Sqlizer) result {
	// this value could be a EntityUID, which can be a variable
	if variable, ok := eval.ToVariable(value); ok {
		isValue = false
		sqlizer = Expr(string(variable))
	}
	return result{isValue: isValue, value: value, sqlizer: sqlizer}
}

func (r result) String() string {
	if r.isValue {
		return "(value: " + r.value.String() + ")"
	}
	sql, args, err := r.ToSql()
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return fmt.Sprintf("(sql: %s, args: %v)", sql, args)
}

func (r result) ToSql() (string, []interface{}, error) {
	return r.sqlizer.ToSql()
}

func (left result) Arg() (interface{}, error) {
	return utils.ValueToGoValue(left.value)
}

func (left result) PgArrayArg() (interface{}, error) {
	arg, err := left.Arg()
	if err != nil {
		return nil, err
	}
	return pq.Array(arg), nil
}

func (left result) Json() (string, error) {
	return utils.ValueToJSON(left.value)
}

func (left result) And(right result) (result, error) {
	if left.isValue {
		if val, err := valueIsTrue(left.value); err != nil {
			return valueToResult(false, nil, nil), err
		} else if val {
			return right, nil
		}
	}
	if right.isValue {
		if val, err := valueIsTrue(right.value); err != nil {
			return valueToResult(false, nil, nil), err
		} else if val {
			return left, nil
		} else {
			return valueToResult(false, nil, AndExpr(left.sqlizer, right.sqlizer)), nil
		}
	}
	return valueToResult(false, nil, AndExpr(left.sqlizer, right.sqlizer)), nil
}

func (left result) Or(right result) (result, error) {
	if left.isValue {
		if val, err := valueIsFalse(left.value); err != nil {
			return valueToResult(false, nil, nil), err
		} else if val {
			return right, nil
		}
	}
	if right.isValue {
		if val, err := valueIsFalse(right.value); err != nil {
			return valueToResult(false, nil, nil), err
		} else if val {
			return left, nil
		}
	}
	return valueToResult(false, nil, OrExpr(left.sqlizer, right.sqlizer)), nil
}

func (left result) Compare(right result, exprStr string) (result, error) {
	if left.isValue {
		arg, err := left.Arg()
		if err != nil {
			return valueToResult(false, nil, nil), err
		}
		return valueToResult(false, nil, Expr(exprStr, arg, right.sqlizer)), nil
	}
	if right.isValue {
		arg, err := right.Arg()
		if err != nil {
			return valueToResult(false, nil, nil), err
		}
		return valueToResult(false, nil, Expr(exprStr, left.sqlizer, arg)), nil
	}
	return valueToResult(false, nil, Expr(exprStr, left.sqlizer, right.sqlizer)), nil
}

// in postgres, contains, containsAny, containsAll are all jsonb operators
// left is jsonb, right is text or text[]
// users.block.contains(User::"alice") => users.block ? 'User::"alice"'
// users.block.containsAny(User::"alice") => users.block ?! array['User::"alice"']
// users.block.containsAll(User::"alice") => users.block ?! array['User::"alice"']
func (left result) JsonCompareText(right result, exprStr string) (result, error) {
	if left.isValue {
		return valueToResult(false, nil, nil), fmt.Errorf("cotains containsAny containsAll left side must be a sql column")
	}
	if right.isValue {
		arg, err := right.Arg()
		if err != nil {
			return valueToResult(false, nil, nil), err
		}
		return valueToResult(false, nil, Expr(exprStr, left.sqlizer, arg)), nil
	}
	return valueToResult(false, nil, Expr(exprStr, left.sqlizer, right.sqlizer)), nil
}

func toSqlOrValue(node ast.IsNode, env eval.Env, mapper FieldMapper) (ret result, err error) {
	if Debug {
		fmt.Println(utils.NString(node), "=>")
		defer func() {
			if err == nil {
				fmt.Println("result", ret.String())
			} else {
				fmt.Println("error", err)
			}
		}()
	}
	switch n := node.(type) {
	case ast.NodeTypeAccess:
		ret, err = toAccess(n, env, mapper)
	case ast.NodeValue:
		ret = valueToResult(true, n.Value, nil)
	case ast.NodeTypeNot:
		ret, err = toSqlNot(n, env, mapper)
	case ast.NodeTypeVariable:
		ret, err = toSqlVariable(n, env, mapper)
	case ast.NodeTypeIn:
		ret, err = toSqlIn(n, env, mapper)
	case ast.NodeTypeAnd, ast.NodeTypeOr, ast.NodeTypeEquals, ast.NodeTypeNotEquals, ast.NodeTypeGreaterThan, ast.NodeTypeGreaterThanOrEqual, ast.NodeTypeLessThan, ast.NodeTypeLessThanOrEqual:
		ret, err = toSqlBinary(n, env, mapper)
	case ast.NodeTypeSub, ast.NodeTypeAdd, ast.NodeTypeMult:
		ret, err = toSqlBinary(n, env, mapper)
	case ast.NodeTypeContains, ast.NodeTypeContainsAll, ast.NodeTypeContainsAny:
		ret, err = toSqlBinary(n, env, mapper)
	case ast.NodeTypeIsEmpty:
		ret, err = toSqlEmpty(n, env, mapper)
	case ast.NodeTypeExtensionCall:
		if terr, ok := eval.ToPartialError(n); ok {
			ret = valueToResult(false, nil, nil)
			err = terr
		} else {
			value, terr := nodeToValue(n, env)
			ret = valueToResult(true, value, nil)
			err = terr
		}
	// node that can only be evaluated to a value or error
	case ast.NodeTypeHas:
		ret, err = toSqlHas(n, env, mapper)
	case ast.NodeTypeGetTag, ast.NodeTypeLike, ast.NodeTypeIfThenElse, ast.NodeTypeIs, ast.NodeTypeIsIn, ast.NodeTypeNegate, ast.NodeTypeRecord, ast.NodeTypeSet:
		value, terr := nodeToValue(n, env)
		ret = valueToResult(true, value, nil)
		err = terr
	default:
		return valueToResult(false, nil, nil), fmt.Errorf("unsupported node type: %T", n)
	}
	return
}

// getBinaryFields returns the operator and the left and right nodes of a binary node
func getBinaryFields(node ast.IsNode) (op string, left, right ast.IsNode) {
	switch n := node.(type) {
	case ast.NodeTypeAnd:
		return "AND", n.Left, n.Right
	case ast.NodeTypeOr:
		return "OR", n.Left, n.Right
	case ast.NodeTypeEquals:
		return "=", n.Left, n.Right
	case ast.NodeTypeNotEquals:
		return "!=", n.Left, n.Right
	case ast.NodeTypeGreaterThan:
		return ">", n.Left, n.Right
	case ast.NodeTypeGreaterThanOrEqual:
		return ">=", n.Left, n.Right
	case ast.NodeTypeLessThan:
		return "<", n.Left, n.Right
	case ast.NodeTypeLessThanOrEqual:
		return "<=", n.Left, n.Right
	case ast.NodeTypeAdd:
		return "+", n.Left, n.Right
	case ast.NodeTypeSub:
		return "-", n.Left, n.Right
	case ast.NodeTypeMult:
		return "*", n.Left, n.Right
	case ast.NodeTypeContains:
		return "??", n.Left, n.Right
	case ast.NodeTypeContainsAll:
		return "??&", n.Left, n.Right
	case ast.NodeTypeContainsAny:
		return "??|", n.Left, n.Right

	default:
		return "", nil, nil
	}
}

func valueIsTrue(value cedar.Value) (bool, error) {
	val, err := utils.ValueToType[cedar.Boolean](value)
	if err != nil {
		return false, err
	}
	return val == cedar.True, nil
}

func valueIsFalse(value cedar.Value) (bool, error) {
	val, err := utils.ValueToType[cedar.Boolean](value)
	if err != nil {
		return false, err
	}
	return val == cedar.False, nil
}

func toSqlBinary(node ast.IsNode, env eval.Env, mapper FieldMapper) (result, error) {
	_, left, right := getBinaryFields(node)
	leftResult, err := toSqlOrValue(left, env, mapper)
	if err != nil {
		return valueToResult(false, nil, nil), err
	}
	rightResult, err := toSqlOrValue(right, env, mapper)
	if err != nil {
		return valueToResult(false, nil, nil), err
	}
	if leftResult.isValue && rightResult.isValue {
		val, err := nodeToValue(node, env)
		if err != nil {
			return valueToResult(false, nil, nil), err
		}
		return valueToResult(true, val, nil), nil
	}
	switch node.(type) {
	case ast.NodeTypeAnd:
		return leftResult.And(rightResult)
	case ast.NodeTypeOr:
		return leftResult.Or(rightResult)
	case ast.NodeTypeEquals:
		return leftResult.Compare(rightResult, "? = ?")
	case ast.NodeTypeNotEquals:
		return leftResult.Compare(rightResult, "? != ?")
	case ast.NodeTypeGreaterThan:
		return leftResult.Compare(rightResult, "? > ?")
	case ast.NodeTypeGreaterThanOrEqual:
		return leftResult.Compare(rightResult, "? >= ?")
	case ast.NodeTypeLessThan:
		return leftResult.Compare(rightResult, "? < ?")
	case ast.NodeTypeLessThanOrEqual:
		return leftResult.Compare(rightResult, "? <= ?")
	case ast.NodeTypeAdd:
		return leftResult.Compare(rightResult, "? + ?")
	case ast.NodeTypeSub:
		return leftResult.Compare(rightResult, "? - ?")
	case ast.NodeTypeMult:
		return leftResult.Compare(rightResult, "? * ?")
	case ast.NodeTypeContains:
		return leftResult.JsonCompareText(rightResult, "? ?? ?")
	case ast.NodeTypeContainsAll:
		return leftResult.JsonCompareText(rightResult, "? ??| ?")
	case ast.NodeTypeContainsAny:
		return leftResult.JsonCompareText(rightResult, "? ??& ?")

	default:
		return valueToResult(false, nil, nil), fmt.Errorf("unsupported node type: %T", node)
	}

}

func toAccess(n ast.NodeTypeAccess, env eval.Env, mapper FieldMapper) (result, error) {
	argResult, err := toSqlOrValue(n.Arg, env, mapper)
	if err != nil {
		return valueToResult(false, nil, nil), err
	}
	if argResult.isValue {
		//this could eval to a varaible as EntityUID
		val, err := eval.Eval(ast.Value(argResult.value).Access(n.Value).AsIsNode(), env)
		if err != nil {
			return valueToResult(false, nil, nil), err
		}
		return valueToResult(true, val, nil), nil
	}
	sql, args, err := ConcatExpr(argResult.sqlizer, ".", n.Value).ToSql()
	if err != nil {
		return valueToResult(false, nil, nil), err
	}
	if mapper != nil {
		field, err := mapper.Map(sql)
		if err != nil {
			return valueToResult(false, nil, nil), err
		}
		sql = field
	}
	return valueToResult(false, nil, newPart(sql, args...)), nil
}

func nodeToValue(n ast.IsNode, env eval.Env) (value cedar.Value, err error) {
	val, err := eval.Eval(n, env)
	if err != nil {
		return nil, err
	}
	return val, nil
}

func toSqlNot(n ast.NodeTypeNot, env eval.Env, mapper FieldMapper) (result, error) {
	argResult, err := toSqlOrValue(n.Arg, env, mapper)
	if err != nil {
		return valueToResult(false, nil, nil), err
	}
	if argResult.isValue {
		val, err := eval.Eval(ast.Not(ast.Value(argResult.value)).AsIsNode(), env)
		if err != nil {
			return valueToResult(false, nil, nil), err
		}
		return valueToResult(true, val, nil), nil
	}
	return valueToResult(false, nil, Expr("NOT (?)", argResult.sqlizer)), nil
}

func toSqlEmpty(n ast.NodeTypeIsEmpty, env eval.Env, mapper FieldMapper) (result, error) {
	argResult, err := toSqlOrValue(n.Arg, env, mapper)
	if err != nil {
		return valueToResult(false, nil, nil), err
	}
	if argResult.isValue {
		val, err := eval.Eval(ast.Value(argResult.value).IsEmpty().AsIsNode(), env)
		if err != nil {
			return valueToResult(false, nil, nil), err
		}
		return valueToResult(true, val, nil), nil
	}
	return valueToResult(false, nil, Expr("? IS NULL", argResult.sqlizer)), nil
}

func toSqlVariable(n ast.NodeTypeVariable, env eval.Env, mapper FieldMapper) (result, error) {
	val, err := eval.Eval(n, env)
	if err != nil {
		return valueToResult(false, nil, nil), err
	}
	// it is a value, but could be a `Variable` value which is EntityUID
	return valueToResult(true, val, nil), nil
}

func toSqlIn(n ast.NodeTypeIn, env eval.Env, mapper FieldMapper) (result, error) {
	leftResult, err := toSqlOrValue(n.Left, env, mapper)
	if err != nil {
		return valueToResult(false, nil, nil), err
	}
	rightResult, err := toSqlOrValue(n.Right, env, mapper)
	if err != nil {
		return valueToResult(false, nil, nil), err
	}

	if leftResult.isValue && rightResult.isValue {
		val, err := eval.Eval(ast.Value(leftResult.value).In(ast.Value(rightResult.value)).AsIsNode(), env)
		if err != nil {
			return valueToResult(false, nil, nil), err
		}
		return valueToResult(true, val, nil), nil
	}

	// principal in viewACL, "User::alice" is in viewACL
	// left must be EntityUID type, right side of in must be a set,
	// so in postgres it is "right ? left::jsonb"
	if leftResult.isValue {
		leftArg, err := leftResult.Arg()
		if err != nil {
			return valueToResult(false, nil, nil), err
		}

		return valueToResult(false, nil, Expr("? ?? ?", rightResult.sqlizer, leftArg)), nil
	}
	if rightResult.isValue {
		// if _, err := utils.ValueToType[cedar.Set](rightResult.value); err != nil {
		// 	return newResult(false, nil, nil), err
		// }
		// rightArg, err := rightResult.Arg()
		// if err != nil {
		// 	return newResult(false, nil, nil), err
		// }

		return valueToResult(false, nil, nil), fmt.Errorf("right side of in must be a variable as sql column")
	}

	return valueToResult(false, nil, Expr("? ?? ?", rightResult.sqlizer, leftResult.sqlizer)), nil
}

func toSqlHas(n ast.NodeTypeHas, env eval.Env, mapper FieldMapper) (result, error) {
	argResult, err := toSqlOrValue(n.Arg, env, mapper)
	if err != nil {
		return valueToResult(false, nil, nil), err
	}
	if argResult.isValue {
		val, err := eval.Eval(ast.Value(argResult.value).Has(n.Value).AsIsNode(), env)
		if err != nil {
			return valueToResult(false, nil, nil), err
		}
		return valueToResult(true, val, nil), nil
	}

	sql, args, err := ConcatExpr(argResult.sqlizer, ".", n.Value).ToSql()
	if err != nil {
		return valueToResult(false, nil, nil), err
	}
	if mapper != nil {
		field, err := mapper.Map(sql)
		if err != nil {
			return valueToResult(false, nil, nil), err
		}
		sql = field
	}

	return valueToResult(false, nil, Expr("? IS NOT NULL", Expr(sql, args...))), nil
}
