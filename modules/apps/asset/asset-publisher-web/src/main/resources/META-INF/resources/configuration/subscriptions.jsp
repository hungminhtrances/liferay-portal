<%--
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
--%>

<%@ include file="/init.jsp" %>

<%
String emailFromName = ParamUtil.getString(request, "preferences--emailFromName--", assetPublisherWebHelper.getEmailFromName(portletPreferences, company.getCompanyId()));
String emailFromAddress = ParamUtil.getString(request, "preferences--emailFromAddress--", assetPublisherWebHelper.getEmailFromAddress(portletPreferences, company.getCompanyId()));

boolean emailAssetEntryAddedEnabled = ParamUtil.getBoolean(request, "preferences--emailAssetEntryAddedEnabled--", assetPublisherWebHelper.getEmailAssetEntryAddedEnabled(portletPreferences));
%>

<liferay-ui:error key="emailAssetEntryAddedBody" message="please-enter-a-valid-body" />
<liferay-ui:error key="emailAssetEntryAddedSubject" message="please-enter-a-valid-subject" />
<liferay-ui:error key="emailFromAddress" message="please-enter-a-valid-email-address" />
<liferay-ui:error key="emailFromName" message="please-enter-a-valid-name" />

<aui:input id="enableEmailSubscription" label="enable-email-subscription" name="preferences--emailAssetEntryAddedEnabled--" type="toggle-switch" value="<%= emailAssetEntryAddedEnabled %>" />

<div class='<%= emailAssetEntryAddedEnabled ? StringPool.BLANK : "hide" %>' id="<portlet:namespace />emailSubscriptionSettings">
	<aui:input cssClass="lfr-input-text-container" label="name" name="preferences--emailFromName--" value="<%= emailFromName %>" />

	<aui:input cssClass="lfr-input-text-container" label="address" name="preferences--emailFromAddress--" value="<%= emailFromAddress %>" />

	<liferay-frontend:email-notification-settings
		emailBodyLocalizedValuesMap="<%= assetPublisherDisplayContext.getEmailAssetEntryAddedBody() %>"
		emailDefinitionTerms="<%= assetPublisherWebHelper.getEmailDefinitionTerms(renderRequest, emailFromAddress, emailFromName) %>"
		emailEnabled="<%= emailAssetEntryAddedEnabled %>"
		emailParam="emailAssetEntryAdded"
		emailSubjectLocalizedValuesMap="<%= assetPublisherDisplayContext.getEmailAssetEntryAddedSubject() %>"
		showEmailEnabled="<%= false %>"
	/>
</div>

<aui:script sandbox="<%= true %>">
	Liferay.Util.toggleBoxes(
		'<portlet:namespace />enableEmailSubscription',
		'<portlet:namespace />emailSubscriptionSettings'
	);
</aui:script>