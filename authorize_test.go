package cedarsqlizer

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/jaredzhou/cedar-sqlizer/sqlizer"
)

var entitiesStr = `
[
    {
        "uid": {
            "type": "User",
            "id": "alice"
        },
        "parents": [
            {
                "type": "Group",
                "id": "admin"
            }
        ],
        "attrs": {
        }
    },
    {
        "uid": {
            "type": "User",
            "id": "bob"
        },
        "attrs": {
        }
    },
    {
        "uid": {
            "type": "User",
            "id": "charlie"
        },
        "attrs": {
            "block": true
        }
    },
    {
        "uid": {
            "type": "Group",
            "id": "admin"
        },
        "attrs": {
        }
    }
]

`

type docMapper struct{}

func (m docMapper) Map(name string) (string, error) {
	validDocFields := []string{"owner", "is_public"}
	if strings.HasPrefix(name, "resource.") {
		field := strings.TrimPrefix(name, "resource.")
		if slices.Contains(validDocFields, field) {
			return "document." + field, nil
		}
	}

	validUserFields := []string{"id", "block"}
	if strings.HasPrefix(name, "users.") {
		field := strings.TrimPrefix(name, "users.")
		if slices.Contains(validUserFields, field) {
			return name, nil
		}
	}

	return name, fmt.Errorf("%s: %w", name, sqlizer.ErrInvalidFieldName)
}

func TestAuthorizeSQL(t *testing.T) {
	t.Parallel()
	psStr := `
	permit(principal, action == Action::"ViewDocument", resource)
	when {context.is_authenticated} 
    when {resource.owner == principal || resource.is_public == true}; 

    permit(principal, action == Action::"ViewDocument", resource)
	when {context.is_authenticated} 
    when {principal in Group::"admin"} ;

	permit(principal, action == Action::"ViewDocument", resource)
    when {!context.is_authenticated} 
	when {resource.is_public == true} ;

    forbid(principal, action == Action::"ViewDocument", resource)
    when {principal has block && principal.block == true} ;
	`
	ps, err := cedar.NewPolicySetFromBytes("", []byte(psStr))
	if err != nil {
		t.Fatal("new policy set error", err)
	}
	var entities types.EntityMap

	err = entities.UnmarshalJSON([]byte(entitiesStr))
	if err != nil {
		t.Fatal("unmarshal entities error", err)
	}
	tests := []struct {
		name      string
		principal string
		context   cedar.Value
		want      string
		args      []interface{}
	}{
		{
			name:      "alice is admin and see all documents",
			principal: "alice",
			context: cedar.NewRecord(cedar.RecordMap{
				"is_authenticated": cedar.Boolean(true),
			}),
			want: "1 = 1",
			args: []interface{}{},
		},
		{
			name:      "bob is normal user and see public documents and his own documents",
			principal: "bob",
			context: cedar.NewRecord(cedar.RecordMap{
				"is_authenticated": cedar.Boolean(true),
			}),
			want: "(document.owner = ? OR document.is_public = ?)",
			args: []interface{}{"bob", true},
		},
		{
			name:      "charlie is blocked and cannot see any documents",
			principal: "charlie",
			context: cedar.NewRecord(cedar.RecordMap{
				"is_authenticated": cedar.Boolean(true),
			}),
			want: "1 = 0",
			args: []interface{}{},
		},
		{
			name:      "unauthenticated user can see public documents",
			principal: "unauthenticated",
			context: cedar.NewRecord(cedar.RecordMap{
				"is_authenticated": cedar.Boolean(false),
			}),
			want: "document.is_public = ?",
			args: []interface{}{true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sql, args, err := AuthorizeSQL(ps, entities, &AuthorizeSQLRequest{
				Principal:   cedar.NewEntityUID("User", cedar.String(tt.principal)),
				Action:      cedar.NewEntityUID("Action", "ViewDocument"),
				Context:     tt.context,
				FieldMapper: docMapper{},
			})
			if err != nil {
				t.Fatal("authorize sql error", err)
			}

			if sql != tt.want {
				t.Fatalf("want %s, got %s", tt.want, sql)
			}
			if len(args) != len(tt.args) {
				t.Fatalf("want args length %d, got %d", len(tt.args), len(args))
			}
			for i, arg := range args {
				if !reflect.DeepEqual(arg, tt.args[i]) {
					t.Fatalf("arg[%d]: want %v, got %v", i, tt.args[i], arg)
				}
			}
		})
	}
}
