/**
 * Copyright (c) 2000-present Liferay, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

package com.liferay.portal.workflow.task.web.permission;

import com.liferay.portal.kernel.model.Role;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.security.permission.PermissionChecker;
import com.liferay.portal.kernel.util.ArrayUtil;
import com.liferay.portal.kernel.workflow.WorkflowTask;
import com.liferay.portal.kernel.workflow.WorkflowTaskAssignee;


import com.liferay.portal.kernel.theme.ThemeDisplay;
import com.liferay.portal.kernel.service.GroupLocalServiceUtil;
import java.util.List;
import com.liferay.portal.kernel.model.Group;
import com.liferay.portal.kernel.exception.PortalException;
/**
 * @author Adam Brandizzi
 */
public class WorkflowTaskPermissionChecker {

	public boolean hasPermission(
		ThemeDisplay themeDisplay, WorkflowTask workflowTask) 
		throws PortalException{
		
		//get all group for current user
		//check if usergroup has permission
		List<Group> groups = GroupLocalServiceUtil.getUserGroups(themeDisplay.getUserId(), true);

		for (Group group : groups) {
			if (_hasPermission(
				group.getGroupId(), workflowTask,
				themeDisplay.getPermissionChecker()
				)) {
				return true;
			}
		}

		if (_hasPermission(
			themeDisplay.getScopeGroupId(), workflowTask,
			themeDisplay.getPermissionChecker()
			)) {
			return true;
		}
		return false;
	}

	private boolean _hasPermission(
		long groupId, WorkflowTask workflowTask,
		PermissionChecker permissionChecker) {

		if (permissionChecker.isOmniadmin() ||
			permissionChecker.isCompanyAdmin()) {

			return true;
		}

		if (permissionChecker.isContentReviewer(
				permissionChecker.getCompanyId(), groupId)) {

			return true;
		}

		long[] roleIds = permissionChecker.getRoleIds(
			permissionChecker.getUserId(), groupId);

		for (WorkflowTaskAssignee workflowTaskAssignee :
				workflowTask.getWorkflowTaskAssignees()) {

			if (isWorkflowTaskAssignableToRoles(
					workflowTaskAssignee, roleIds) ||
				isWorkflowTaskAssignableToUser(
					workflowTaskAssignee, permissionChecker.getUserId())) {

				return true;
			}
		}

		return false;
	}

	protected boolean isWorkflowTaskAssignableToRoles(
		WorkflowTaskAssignee workflowTaskAssignee, long[] roleIds) {

		String assigneeClassName = workflowTaskAssignee.getAssigneeClassName();

		if (!assigneeClassName.equals(Role.class.getName())) {
			return false;
		}

		if (ArrayUtil.contains(
				roleIds, workflowTaskAssignee.getAssigneeClassPK())) {

			return true;
		}

		return false;
	}

	protected boolean isWorkflowTaskAssignableToUser(
		WorkflowTaskAssignee workflowTaskAssignee, long userId) {

		String assigneeClassName = workflowTaskAssignee.getAssigneeClassName();

		if (!assigneeClassName.equals(User.class.getName())) {
			return false;
		}

		if (workflowTaskAssignee.getAssigneeClassPK() == userId) {
			return true;
		}

		return false;
	}

}