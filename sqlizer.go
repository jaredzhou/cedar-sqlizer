package sqlizer

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/eval"
)

var (
	sqlTrue  = "1 = 1"
	sqlFalse = "1 = 0"
)

type FieldMapper interface {
	Map(name string) (string, bool)
}

type defaultFieldMapper struct{}

func (m defaultFieldMapper) Map(name string) (string, bool) {
	return name, true
}

type Sqlizer interface {
	ToSql() (string, []interface{}, error)
}

type expr struct {
	sql  string
	args []interface{}
}

func Expr(sql string, args ...interface{}) Sqlizer {
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
		return e.sql, e.args, nil
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
			// escaped "??"; append it and step past
			buf.WriteString(sp[:i+2])
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
		sql = fmt.Sprintf("(%s)", strings.Join(sqlParts, c.sep))
	}
	return
}

func AndExpr(parts ...Sqlizer) Sqlizer {
	return conj{parts: parts, sep: " AND ", defaultExpr: sqlTrue}
}

func OrExpr(parts ...Sqlizer) Sqlizer {
	return conj{parts: parts, sep: " OR ", defaultExpr: sqlFalse}
}

func ToSql(node ast.IsNode, env eval.Env, mapper FieldMapper) (sql string, args []interface{}, err error) {
	isValue, value, sqlizer, err := toSqlOrValue(node, env, mapper)
	if err != nil {
		return "", nil, err
	}
	if isValue {
		val, err := ValueToType[cedar.Boolean](value)
		if err != nil {
			return "", nil, err
		}
		if val {
			return sqlTrue, nil, nil
		}
		return sqlFalse, nil, nil
	}
	return sqlizer.ToSql()
}

func toSqlOrValue(node ast.IsNode, env eval.Env, mapper FieldMapper) (isValue bool, value cedar.Value, sqlizer Sqlizer, err error) {
	switch n := node.(type) {
	case ast.NodeTypeAccess:
		return toAccess(n, env, mapper)
	case ast.NodeValue:
		return true, n.Value, nil, nil
	case ast.NodeTypeNot:
		return toSqlNot(n, env, mapper)
	case ast.NodeTypeVariable:
		return toSqlVariable(n, env, mapper)
	case ast.NodeTypeIn:
		return toSqlIn(n, env, mapper)
	case ast.NodeTypeAnd:
		return toSqlAnd(n, env, mapper)
	case ast.NodeTypeOr:
		return toSqlOr(n, env, mapper)
	case ast.NodeTypeEquals, ast.NodeTypeNotEquals, ast.NodeTypeGreaterThan, ast.NodeTypeGreaterThanOrEqual, ast.NodeTypeLessThan, ast.NodeTypeLessThanOrEqual:
		return toSqlBinary(n, env, mapper)
	case ast.NodeTypeSub, ast.NodeTypeAdd, ast.NodeTypeMult:
		return toSqlBinary(n, env, mapper)
	case ast.NodeTypeContains, ast.NodeTypeContainsAll, ast.NodeTypeContainsAny:
		return toSqlBinary(n, env, mapper)
	case ast.NodeTypeIsEmpty:
		return toSqlEmpty(n, env, mapper)
	case ast.NodeTypeExtensionCall:
		if eval.IsPartialError(n) {
			strValue, _ := toValue(n.Args[0], env)
			str, _ := valueToArg(strValue)
			return false, nil, nil, errors.New(str.(string))
		}
		value, err = toValue(n, env)
		return true, value, nil, err
	// node that can only be evaluated to a value or error
	case ast.NodeTypeHas, ast.NodeTypeGetTag, ast.NodeTypeLike, ast.NodeTypeIfThenElse, ast.NodeTypeIs, ast.NodeTypeIsIn, ast.NodeTypeNegate, ast.NodeTypeRecord, ast.NodeTypeSet:
		value, err = toValue(n, env)
		return true, value, nil, err
	default:
		return false, nil, nil, fmt.Errorf("unsupported node type: %T", n)
	}
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
		return "@>", n.Left, n.Right
	case ast.NodeTypeContainsAll:
		return "@>", n.Left, n.Right
	case ast.NodeTypeContainsAny:
		return "?!", n.Left, n.Right

	default:
		return "", nil, nil
	}
}

// this is called after partial so no value
func toSqlAnd(n ast.IsNode, env eval.Env, mapper FieldMapper) (isValue bool, value cedar.Value, sqlizer Sqlizer, err error) {
	_, left, right := getBinaryFields(n)
	leftIsValue, leftValue, leftSqlizer, err := toSqlOrValue(left, env, mapper)
	if err != nil {
		return false, nil, nil, err
	}
	rightIsValue, rightValue, rightSqlizer, err := toSqlOrValue(right, env, mapper)
	if err != nil {
		return false, nil, nil, err
	}
	if val, err := valueIsTrue(leftIsValue, leftValue); err != nil {
		return false, nil, nil, err
	} else if val {
		return false, nil, rightSqlizer, nil
	}
	if val, err := valueIsTrue(rightIsValue, rightValue); err != nil {
		return false, nil, nil, err
	} else if val {
		return false, nil, leftSqlizer, nil
	}
	return false, nil, AndExpr(leftSqlizer, rightSqlizer), nil
}

func toSqlOr(n ast.IsNode, env eval.Env, mapper FieldMapper) (isValue bool, value cedar.Value, sqlizer Sqlizer, err error) {
	_, left, right := getBinaryFields(n)
	leftIsValue, leftValue, leftSqlizer, err := toSqlOrValue(left, env, mapper)
	if err != nil {
		return false, nil, nil, err
	}
	rightIsValue, rightValue, rightSqlizer, err := toSqlOrValue(right, env, mapper)
	if err != nil {
		return false, nil, nil, err
	}
	if val, err := valueIsFalse(leftIsValue, leftValue); err != nil {
		return false, nil, nil, err
	} else if val {
		return false, nil, leftSqlizer, nil
	}
	if val, err := valueIsFalse(rightIsValue, rightValue); err != nil {
		return false, nil, nil, err
	} else if val {
		return false, nil, rightSqlizer, nil
	}
	return false, nil, OrExpr(leftSqlizer, rightSqlizer), nil
}

func valueIsTrue(isValue bool, value cedar.Value) (bool, error) {
	if !isValue {
		return false, nil
	}
	val, err := ValueToType[cedar.Boolean](value)
	if err != nil {
		return false, err
	}
	return val == cedar.True, nil
}

func valueIsFalse(isValue bool, value cedar.Value) (bool, error) {
	if !isValue {
		return false, nil
	}
	val, err := ValueToType[cedar.Boolean](value)
	if err != nil {
		return false, err
	}
	return val == cedar.False, nil
}

func toSqlBinary(n ast.IsNode, env eval.Env, mapper FieldMapper) (isValue bool, value cedar.Value, sqlizer Sqlizer, err error) {
	op, left, right := getBinaryFields(n)
	leftIsValue, leftValue, leftSqlizer, err := toSqlOrValue(left, env, mapper)
	if err != nil {
		return false, nil, nil, err
	}
	rightIsValue, rightValue, rightSqlizer, err := toSqlOrValue(right, env, mapper)
	if err != nil {
		return false, nil, nil, err
	}
	switch {
	case leftIsValue && rightIsValue:
		val, err := eval.Eval(n, env)
		if err != nil {
			return false, nil, nil, err
		}
		return true, val, nil, nil
	case leftIsValue:
		valToArg, err := valueToArg(leftValue)
		if err != nil {
			return false, nil, nil, err
		}
		if _, ok := leftValue.(cedar.EntityUID); ok {
			if _, lok := right.(ast.NodeTypeVariable); lok {
				sql := Expr("? "+op+" ?.id", valToArg, rightSqlizer)
				return false, nil, sql, nil
			}
			sql := Expr("? "+op+" ?", valToArg, rightSqlizer)
			return false, nil, sql, nil
		}
		sql := Expr("? "+op+" ?", valToArg, rightSqlizer)
		return false, nil, sql, nil
	case rightIsValue:
		valToArg, err := valueToArg(rightValue)
		if err != nil {
			return false, nil, nil, err
		}
		if _, ok := rightValue.(cedar.EntityUID); ok {
			if _, lok := left.(ast.NodeTypeVariable); lok {
				sql := Expr("?.id "+op+" ?", leftSqlizer, valToArg)
				return false, nil, sql, nil
			}
			sql := Expr("? "+op+" ?", leftSqlizer, valToArg)
			return false, nil, sql, nil
		}
		sql := Expr("? "+op+" ?", leftSqlizer, valToArg)
		return false, nil, sql, nil
	default:
		sql := Expr("? "+op+" ?", leftSqlizer, rightSqlizer)
		return false, nil, sql, nil
	}
}

func toAccess(n ast.NodeTypeAccess, env eval.Env, mapper FieldMapper) (isValue bool, value cedar.Value, sqlizer Sqlizer, err error) {
	isValue, value, sqlizer, err = toSqlOrValue(n.Arg, env, mapper)
	if err != nil {
		return false, nil, nil, err
	}
	if isValue {
		val, err := eval.Eval(ast.Value(value).Access(n.Value).AsIsNode(), env)
		if err != nil {
			return false, nil, nil, err
		}
		return true, val, nil, nil
	}
	sql, args, err := ConcatExpr(sqlizer, ".", n.Value).ToSql()
	if err != nil {
		return false, nil, nil, err
	}
	if mapper != nil {
		field, ok := mapper.Map(sql)
		if ok {
			sql = field
		}
	}
	return false, nil, newPart(sql, args...), nil
}

func toValue(n ast.IsNode, env eval.Env) (value cedar.Value, err error) {
	val, err := eval.Eval(n, env)
	if err != nil {
		return nil, err
	}
	return val, nil
}

func toSqlNot(n ast.NodeTypeNot, env eval.Env, mapper FieldMapper) (isValue bool, value cedar.Value, sqlizer Sqlizer, err error) {
	isValue, value, sqlizer, err = toSqlOrValue(n.Arg, env, mapper)
	if err != nil {
		return false, nil, nil, err
	}
	if isValue {
		val, err := eval.Eval(ast.Not(ast.Value(value)).AsIsNode(), env)
		if err != nil {
			return false, nil, nil, err
		}
		return true, val, nil, nil
	}
	return false, nil, Expr("NOT (?)", sqlizer), nil
}

func toSqlEmpty(n ast.NodeTypeIsEmpty, env eval.Env, mapper FieldMapper) (isValue bool, value cedar.Value, sqlizer Sqlizer, err error) {
	isValue, value, sqlizer, err = toSqlOrValue(n.Arg, env, mapper)
	if err != nil {
		return false, nil, nil, err
	}
	if isValue {
		val, err := eval.Eval(ast.Value(value).IsEmpty().AsIsNode(), env)
		if err != nil {
			return false, nil, nil, err
		}
		return true, val, nil, nil
	}
	return false, nil, Expr("? IS NULL", sqlizer), nil
}

func toSqlVariable(n ast.NodeTypeVariable, env eval.Env, mapper FieldMapper) (isValue bool, value cedar.Value, sqlizer Sqlizer, err error) {
	val, err := eval.Eval(n, env)
	if err != nil {
		return false, nil, nil, err
	}
	if !eval.IsVariable(val) {
		return true, val, nil, nil
	}
	return false, nil, newPart(n.Name.String()), nil
}

func toSqlIn(n ast.NodeTypeIn, env eval.Env, mapper FieldMapper) (isValue bool, value cedar.Value, sqlizer Sqlizer, err error) {
	leftIsValue, leftValue, leftSqlizer, err := toSqlOrValue(n.Left, env, mapper)
	if err != nil {
		return false, nil, nil, err
	}
	rightIsValue, rightValue, rightSqlizer, err := toSqlOrValue(n.Right, env, mapper)
	if err != nil {
		return false, nil, nil, err
	}

	if leftIsValue && rightIsValue {
		val, err := eval.Eval(ast.Value(leftValue).In(ast.Value(rightValue)).AsIsNode(), env)
		if err != nil {
			return false, nil, nil, err
		}
		return true, val, nil, nil
	}
	if !rightIsValue {
		return false, nil, nil, fmt.Errorf("right side of IN must be a set, not %T", rightSqlizer)
	}
	if _, err := ValueToType[cedar.Set](rightValue); err != nil {
		return false, nil, nil, err
	}
	rightArg, err := valueToArg(rightValue)
	if err != nil {
		return false, nil, nil, err
	}
	expr := Expr("? IN ?", leftSqlizer, rightArg)
	return false, nil, expr, nil
}

func valueToArg(v cedar.Value) (interface{}, error) {
	switch v := v.(type) {
	case cedar.String:
		return string(v), nil
	case cedar.EntityUID:
		return string(v.ID), nil
	case cedar.Long:
		return int64(v), nil
	case cedar.Boolean:
		return bool(v), nil
	case cedar.Decimal:
		return v.String(), nil
	case cedar.Datetime:
		return v.Time(), nil
	case cedar.IPAddr:
		return nil, fmt.Errorf("unsupported value type for SQL: %T", v)
	case cedar.Set:
		var args []interface{}
		for item := range v.All() {
			arg, err := valueToArg(item)
			if err != nil {
				return nil, err
			}
			args = append(args, arg)
		}
		return args, nil
	case cedar.Record:
		return nil, fmt.Errorf("unsupported value type for SQL: %T", v)
	}
	return nil, fmt.Errorf("%w: expected string, got %v", eval.ErrType, eval.TypeName(v))
}

func ValueToType[T cedar.Value](v cedar.Value) (T, error) {
	var zero T
	vv, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("%w: expected %T, got %v", eval.ErrType, zero, eval.TypeName(v))
	}
	return vv, nil
}
