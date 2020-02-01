// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"net/http"
	"strings"

	"github.com/mattermost/mattermost-server/v5/mlog"
	"github.com/mattermost/mattermost-server/v5/model"
)

var moderatedPermissions map[string]bool

func init() {
	moderatedPermissions = map[string]bool{
		model.PERMISSION_ADD_REACTION.Id:                   true,
		model.PERMISSION_REMOVE_REACTION.Id:                true,
		model.PERMISSION_CREATE_POST.Id:                    true,
		model.PERMISSION_MANAGE_PUBLIC_CHANNEL_MEMBERS.Id:  true,
		model.PERMISSION_MANAGE_PRIVATE_CHANNEL_MEMBERS.Id: true,
		// model.PERMISSION_USE_CHANNEL_MENTIONS:              true,
	}
}

func (a *App) MakePermissionError(permission *model.Permission) *model.AppError {
	return model.NewAppError("Permissions", "api.context.permissions.app_error", nil, "userId="+a.Session.UserId+", "+"permission="+permission.Id, http.StatusForbidden)
}

func (a *App) SessionHasPermissionTo(session model.Session, permission *model.Permission) bool {
	return a.RolesGrantPermission(session.GetUserRoles(), permission.Id)
}

func (a *App) SessionHasPermissionToTeam(session model.Session, teamId string, permission *model.Permission) bool {
	if teamId == "" {
		return false
	}

	teamMember := session.GetTeamByTeamId(teamId)
	if teamMember != nil {
		if a.RolesGrantPermission(teamMember.GetRoles(), permission.Id) {
			return true
		}
	}

	return a.RolesGrantPermission(session.GetUserRoles(), permission.Id)
}

func (a *App) SessionHasPermissionToChannel(session model.Session, channelId string, permission *model.Permission) bool {
	if channelId == "" {
		return false
	}

	ids, err := a.Srv.Store.Channel().GetAllChannelMembersForUser(session.UserId, true, true)

	var channelRoles []string
	if err == nil {
		if roles, ok := ids[channelId]; ok {
			channelRoles = strings.Fields(roles)
			if a.ChannelRolesGrantPermission(channelRoles, permission.Id, channelId) {
				return true
			}
		}
	}

	channel, err := a.GetChannel(channelId)
	if err == nil && channel.TeamId != "" {
		return a.SessionHasPermissionToTeam(session, channel.TeamId, permission)
	}

	if err != nil && err.StatusCode == http.StatusNotFound {
		return false
	}

	return a.SessionHasPermissionTo(session, permission)
}

func (a *App) SessionHasPermissionToChannelByPost(session model.Session, postId string, permission *model.Permission) bool {
	if channelMember, err := a.Srv.Store.Channel().GetMemberForPost(postId, session.UserId); err == nil {

		if a.RolesGrantPermission(channelMember.GetRoles(), permission.Id) {
			return true
		}
	}

	if channel, err := a.Srv.Store.Channel().GetForPost(postId); err == nil {
		if channel.TeamId != "" {
			return a.SessionHasPermissionToTeam(session, channel.TeamId, permission)
		}
	}

	return a.SessionHasPermissionTo(session, permission)
}

func (a *App) SessionHasPermissionToUser(session model.Session, userId string) bool {
	if userId == "" {
		return false
	}

	if session.UserId == userId {
		return true
	}

	if a.SessionHasPermissionTo(session, model.PERMISSION_EDIT_OTHER_USERS) {
		return true
	}

	return false
}

func (a *App) SessionHasPermissionToUserOrBot(session model.Session, userId string) bool {
	if a.SessionHasPermissionToUser(session, userId) {
		return true
	}

	if err := a.SessionHasPermissionToManageBot(session, userId); err == nil {
		return true
	}

	return false
}

func (a *App) HasPermissionTo(askingUserId string, permission *model.Permission) bool {
	user, err := a.GetUser(askingUserId)
	if err != nil {
		return false
	}

	roles := user.GetRoles()

	return a.RolesGrantPermission(roles, permission.Id)
}

func (a *App) HasPermissionToTeam(askingUserId string, teamId string, permission *model.Permission) bool {
	if teamId == "" || askingUserId == "" {
		return false
	}

	teamMember, err := a.GetTeamMember(teamId, askingUserId)
	if err != nil {
		return false
	}

	roles := teamMember.GetRoles()

	if a.RolesGrantPermission(roles, permission.Id) {
		return true
	}

	return a.HasPermissionTo(askingUserId, permission)
}

func (a *App) HasPermissionToChannel(askingUserId string, channelId string, permission *model.Permission) bool {
	if channelId == "" || askingUserId == "" {
		return false
	}

	channelMember, err := a.GetChannelMember(channelId, askingUserId)
	if err == nil {
		roles := channelMember.GetRoles()
		if a.RolesGrantPermission(roles, permission.Id) {
			return true
		}
	}

	var channel *model.Channel
	channel, err = a.GetChannel(channelId)
	if err == nil {
		return a.HasPermissionToTeam(askingUserId, channel.TeamId, permission)
	}

	return a.HasPermissionTo(askingUserId, permission)
}

func (a *App) HasPermissionToChannelByPost(askingUserId string, postId string, permission *model.Permission) bool {
	if channelMember, err := a.Srv.Store.Channel().GetMemberForPost(postId, askingUserId); err == nil {
		if a.RolesGrantPermission(channelMember.GetRoles(), permission.Id) {
			return true
		}
	}

	if channel, err := a.Srv.Store.Channel().GetForPost(postId); err == nil {
		return a.HasPermissionToTeam(askingUserId, channel.TeamId, permission)
	}

	return a.HasPermissionTo(askingUserId, permission)
}

func (a *App) HasPermissionToUser(askingUserId string, userId string) bool {
	if askingUserId == userId {
		return true
	}

	if a.HasPermissionTo(askingUserId, model.PERMISSION_EDIT_OTHER_USERS) {
		return true
	}

	return false
}

func (a *App) RolesGrantPermission(roleNames []string, permissionId string) bool {
	roles, err := a.GetRolesByNames(roleNames)
	if err != nil {
		// This should only happen if something is very broken. We can't realistically
		// recover the situation, so deny permission and log an error.
		mlog.Error("Failed to get roles from database with role names: "+strings.Join(roleNames, ",")+" ", mlog.Err(err))
		return false
	}

	return rolesPermitPermission(roles, permissionId)
}

func (a *App) ChannelRolesGrantPermission(roleNames []string, permissionID, channelID string) bool {
	// If the permission is moderated (i.e. meant to be controlled by the channel scheme) then use the normal
	// permissions logic.
	if _, ok := moderatedPermissions[permissionID]; ok {
		return a.RolesGrantPermission(roleNames, permissionID)
	}

	// Get the channel for the team id.
	channel, err := a.Srv.Store.Channel().Get(channelID, true)
	if err != nil {
		return false
	}

	// Get the team for the team scheme id.
	team, err := a.Srv.Store.Team().Get(channel.TeamId)
	if err != nil {
		return false
	}

	// Determine which higher-scoped scheme to use, namely the system scheme or the team scheme.
	if team.SchemeId == nil {
		roleNames = []string{model.CHANNEL_GUEST_ROLE_ID, model.CHANNEL_USER_ROLE_ID, model.CHANNEL_ADMIN_ROLE_ID}
	} else {
		scheme, err := a.Srv.Store.Scheme().Get(*team.SchemeId)
		if err != nil {
			return false
		}
		roleNames = []string{scheme.DefaultChannelGuestRole, scheme.DefaultChannelUserRole, scheme.DefaultChannelAdminRole}
	}

	roles, err := a.Srv.Store.Role().GetByNames(roleNames)
	if err != nil {
		return false
	}

	return rolesPermitPermission(roles, permissionID)
}

func rolesPermitPermission(roles []*model.Role, permissionID string) bool {
	for _, role := range roles {
		if role.DeleteAt != 0 {
			continue
		}

		permissions := role.Permissions
		for _, permission := range permissions {
			if permission == permissionID {
				return true
			}
		}
	}

	return false
}

// SessionHasPermissionToManageBot returns nil if the session has access to manage the given bot.
// This function deviates from other authorization checks in returning an error instead of just
// a boolean, allowing the permission failure to be exposed with more granularity.
func (a *App) SessionHasPermissionToManageBot(session model.Session, botUserId string) *model.AppError {
	existingBot, err := a.GetBot(botUserId, true)
	if err != nil {
		return err
	}

	if existingBot.OwnerId == session.UserId {
		if !a.SessionHasPermissionTo(session, model.PERMISSION_MANAGE_BOTS) {
			if !a.SessionHasPermissionTo(session, model.PERMISSION_READ_BOTS) {
				// If the user doesn't have permission to read bots, pretend as if
				// the bot doesn't exist at all.
				return model.MakeBotNotFoundError(botUserId)
			}
			return a.MakePermissionError(model.PERMISSION_MANAGE_BOTS)
		}
	} else {
		if !a.SessionHasPermissionTo(session, model.PERMISSION_MANAGE_OTHERS_BOTS) {
			if !a.SessionHasPermissionTo(session, model.PERMISSION_READ_OTHERS_BOTS) {
				// If the user doesn't have permission to read others' bots,
				// pretend as if the bot doesn't exist at all.
				return model.MakeBotNotFoundError(botUserId)
			}
			return a.MakePermissionError(model.PERMISSION_MANAGE_OTHERS_BOTS)
		}
	}

	return nil
}
