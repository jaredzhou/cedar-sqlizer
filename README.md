# Cedar SQLizer
Cedar SQLizer is an authorization module based on [cedar-go](https://github.com/cedar-policy/cedar-go) that converts Cedar policy partial evaluation results into SQL query conditions. This allows you to seamlessly integrate Cedar authorization policies with your database queries.


## Quick Start

### 1. Define Your Policies

```cedar
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
```

### 2. Define Your Entities

```json
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
        "attrs": {}
    },
    {
        "uid": {
            "type": "User",
            "id": "bob"
        },
        "attrs": {}
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
        "attrs": {}
    }
]
```

### 3. Create Field Mapper

```go
type docMapper struct{}

func (m docMapper) Map(name string) (string, error) {
	validDocFields := []string{"owner", "is_public"}
	if strings.HasPrefix(name, "resource.") {
		field := strings.TrimPrefix(name, "resource.")
		if slices.Contains(validDocFields, field) {
			return "document." + field, nil
		}
	}
	return name, fmt.Errorf("%s: %w", name, sqlizer.ErrInvalidFieldName)
}
```

### 4. Generate SQL Conditions

```go
sql, args, err := AuthorizeSQL(ps, entities, &AuthorizeSQLRequest{
    Principal:   cedar.NewEntityUID("User", cedar.String("bob")),
    Action:      cedar.NewEntityUID("Action", "ViewDocument"),
    Context:     cedar.NewRecord(cedar.RecordMap{
        "is_authenticated": cedar.Boolean(true),
    }),
    FieldMapper: docMapper{},
})
```

## Example Results

Based on the policies above, here are the SQL conditions generated for different users:

| User | Role | SQL Condition |
|------|------|---------------|
| alice | Admin | `1 = 1` |
| bob | Normal User | `(document.owner = ? OR document.is_public = ?)` |
| charlie | Blocked User | `1 = 0` |
| unauthenticated | Guest | `document.is_public = ?` |

## Usage in Database Queries

```go
// Example: Query documents for a specific user
sql, args, err := AuthorizeSQL(policies, entities, &AuthorizeSQLRequest{
    Principal:   userEntity,
    Action:      cedar.NewEntityUID("Action", "ViewDocument"),
    Context:     context,
    FieldMapper: docMapper{},
})
if err != nil {
    return err
}

query := fmt.Sprintf("SELECT * FROM documents WHERE %s", sql)
rows, err := db.Query(query, args...)
```

## API Reference

### AuthorizeSQLRequest

```go
type AuthorizeSQLRequest struct {
    Principal   cedar.EntityUID
    Action      cedar.EntityUID
    Context     cedar.Value
    FieldMapper FieldMapper
}
```

### FieldMapper Interface

```go
type FieldMapper interface {
    Map(name string) (string, error)
}
```

## Related Links

- [Cedar Policy Language](https://docs.cedarpolicy.com/) - Official Cedar documentation
- [cedar-go](https://github.com/cedar-policy/cedar-go) - Go implementation of Cedar
- [Cedar Project](https://www.cedarpolicy.com/) - Cedar policy language homepage