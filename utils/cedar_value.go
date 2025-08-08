package utils

import (
	"encoding/json"
	"fmt"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/eval"
)

func ValueToType[T cedar.Value](v cedar.Value) (T, error) {
	var zero T
	vv, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("%w: expected %T, got %v", eval.ErrType, zero, eval.TypeName(v))
	}
	return vv, nil
}

func ValueToGoValue(v cedar.Value) (interface{}, error) {
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
			arg, err := ValueToGoValue(item)
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

func ValueToJSON(v cedar.Value) (string, error) {
	goValue, err := ValueToGoValue(v)
	if err != nil {
		return "", err
	}
	jsonBytes, err := json.Marshal(goValue)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}
