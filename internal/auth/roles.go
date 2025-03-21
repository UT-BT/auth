package auth

import (
	"github.com/supabase-community/auth-go/types"
)

// Role represents a user role in the system
type Role struct {
	Name        string
	Level       int
	Permissions []string
}

// Available roles in the system
var (
	RoleSuperUser = Role{
		Name:  "super_user",
		Level: 4,
		Permissions: []string{
			"manage_users",
			"manage_roles",
			"manage_system",
			"view_admin_panel",
			"moderate_content",
			"create_content",
		},
	}

	RoleAdmin = Role{
		Name:  "admin",
		Level: 3,
		Permissions: []string{
			"manage_users",
			"view_admin_panel",
			"moderate_content",
			"create_content",
		},
	}

	RoleModerator = Role{
		Name:  "moderator",
		Level: 2,
		Permissions: []string{
			"moderate_content",
			"create_content",
		},
	}

	RoleUser = Role{
		Name:  "user",
		Level: 1,
		Permissions: []string{
			"create_content",
		},
	}
)

// RoleManager handles role-related operations
type RoleManager struct {
	roles map[string]Role
}

// NewRoleManager creates a new RoleManager instance
func NewRoleManager() *RoleManager {
	rm := &RoleManager{
		roles: make(map[string]Role),
	}

	rm.registerRole(RoleSuperUser)
	rm.registerRole(RoleAdmin)
	rm.registerRole(RoleModerator)
	rm.registerRole(RoleUser)

	return rm
}

// registerRole adds a role to the manager
func (rm *RoleManager) registerRole(role Role) {
	rm.roles[role.Name] = role
}

// GetUserRole returns the user's role from their metadata
func (rm *RoleManager) GetUserRole(user *types.UserResponse) Role {
	if user == nil || user.AppMetadata == nil {
		return RoleUser
	}

	roleName, ok := user.AppMetadata["role"].(string)
	if !ok {
		return RoleUser
	}

	role, exists := rm.roles[roleName]
	if !exists {
		return RoleUser
	}

	return role
}

// HasPermission checks if a role has a specific permission
func (rm *RoleManager) HasPermission(role Role, permission string) bool {
	for _, p := range role.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasRequiredRole checks if a user's role has sufficient privileges
func (rm *RoleManager) HasRequiredRole(userRole Role, requiredRole Role) bool {
	return userRole.Level >= requiredRole.Level
}

// GetAllPermissions returns all permissions for a role, including inherited ones
func (rm *RoleManager) GetAllPermissions(role Role) []string {
	permissions := make(map[string]bool)

	for _, r := range rm.roles {
		if r.Level <= role.Level {
			for _, p := range r.Permissions {
				permissions[p] = true
			}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(permissions))
	for p := range permissions {
		result = append(result, p)
	}

	return result
}
