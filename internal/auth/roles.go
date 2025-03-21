package auth

import (
	"github.com/rs/zerolog/log"
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
	log.Debug().Msg("Initializing role manager")
	rm := &RoleManager{
		roles: make(map[string]Role),
	}

	rm.registerRole(RoleSuperUser)
	rm.registerRole(RoleAdmin)
	rm.registerRole(RoleModerator)
	rm.registerRole(RoleUser)

	log.Debug().Int("role_count", len(rm.roles)).Msg("Role manager initialized")
	return rm
}

// registerRole adds a role to the manager
func (rm *RoleManager) registerRole(role Role) {
	log.Debug().Str("role_name", role.Name).Int("level", role.Level).Msg("Registering role")
	rm.roles[role.Name] = role
}

// GetUserRole returns the user's role from their metadata
func (rm *RoleManager) GetUserRole(user *types.UserResponse) Role {
	if user == nil || user.AppMetadata == nil {
		log.Debug().Msg("No user metadata found, defaulting to user role")
		return RoleUser
	}

	roleName, ok := user.AppMetadata["role"].(string)
	if !ok {
		log.Debug().Msg("No valid role found in metadata, defaulting to user role")
		return RoleUser
	}

	role, exists := rm.roles[roleName]
	if !exists {
		log.Warn().Str("role_name", roleName).Msg("Unknown role found in metadata, defaulting to user role")
		return RoleUser
	}

	log.Debug().Str("role_name", role.Name).Str("user_id", user.ID.String()).Msg("Retrieved user role")
	return role
}

// HasPermission checks if a role has a specific permission
func (rm *RoleManager) HasPermission(role Role, permission string) bool {
	hasPermission := false
	for _, p := range role.Permissions {
		if p == permission {
			hasPermission = true
			break
		}
	}
	log.Debug().
		Str("role", role.Name).
		Str("permission", permission).
		Bool("has_permission", hasPermission).
		Msg("Checked role permission")
	return hasPermission
}

// HasRequiredRole checks if a user's role has sufficient privileges
func (rm *RoleManager) HasRequiredRole(userRole Role, requiredRole Role) bool {
	hasRole := userRole.Level >= requiredRole.Level
	log.Debug().
		Str("user_role", userRole.Name).
		Int("user_level", userRole.Level).
		Str("required_role", requiredRole.Name).
		Int("required_level", requiredRole.Level).
		Bool("has_role", hasRole).
		Msg("Checked role requirement")
	return hasRole
}

// GetAllPermissions returns all permissions for a role, including inherited ones
func (rm *RoleManager) GetAllPermissions(role Role) []string {
	log.Debug().Str("role", role.Name).Msg("Getting all permissions for role")
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

	log.Debug().
		Str("role", role.Name).
		Int("permission_count", len(result)).
		Msg("Retrieved all permissions for role")
	return result
}
