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
SiteAdministrationPanelCategoryDisplayContext siteAdministrationPanelCategoryDisplayContext = new SiteAdministrationPanelCategoryDisplayContext(liferayPortletRequest, liferayPortletResponse, null);

Group group = siteAdministrationPanelCategoryDisplayContext.getGroup();
PanelCategory panelCategory = siteAdministrationPanelCategoryDisplayContext.getPanelCategory();

PortletURL portletURL = PortletURLFactoryUtil.create(request, ProductNavigationProductMenuPortletKeys.PRODUCT_NAVIGATION_PRODUCT_MENU, RenderRequest.RENDER_PHASE);

portletURL.setParameter("mvcPath", "/portlet/pages_tree.jsp");
portletURL.setParameter("selPpid", portletDisplay.getId());
portletURL.setWindowState(LiferayWindowState.EXCLUSIVE);
%>

<c:if test="<%= (group != null) && (group.getType() != GroupConstants.TYPE_DEPOT) && !group.isCompany() %>">
	<div class="icon-pages-tree">
		<liferay-ui:icon
			icon="pages-tree"
			id="pagesTreeSidenavToggleId"
			label="<%= false %>"
			linkCssClass="icon-monospaced"
			markupView="lexicon"
			message="find-a-page"
			url="javascript:;"
		/>
	</div>

	<aui:script sandbox="<%= true %>">
		var pagesTreeToggle = document.getElementById(
			'<portlet:namespace />pagesTreeSidenavToggleId'
		);

		pagesTreeToggle.addEventListener('click', function (event) {
			Liferay.Util.Session.set(
				'com.liferay.product.navigation.product.menu.web_pagesTreeState',
				'open'
			).then(function () {
				Liferay.Util.fetch('<%= portletURL.toString() %>')
					.then(function (response) {
						if (!response.ok) {
							throw new Error(
								'<liferay-ui:message key="an-unexpected-error-occurred" />'
							);
						}

						return response.text();
					})
					.then(function (response) {
						var sidebar = document.querySelector(
							'.lfr-product-menu-sidebar .sidebar-body'
						);

						sidebar.innerHTML = '';

						var range = document.createRange();
						range.selectNode(sidebar);

						var fragment = range.createContextualFragment(response);

						var pagesTree = document.createElement('div');
						pagesTree.setAttribute('class', 'pages-tree');
						pagesTree.appendChild(fragment);

						sidebar.appendChild(pagesTree);
					});
			});
		});
	</aui:script>
</c:if>

<c:if test="<%= siteAdministrationPanelCategoryDisplayContext.isShowSiteSelector() %>">
	<div class="icon-sites">
		<liferay-ui:icon
			icon="sites"
			id="manageSitesLink"
			label="<%= false %>"
			linkCssClass="icon-monospaced"
			markupView="lexicon"
			message="go-to-other-site-or-library"
			url="javascript:;"
		/>
	</div>

	<%
	String eventName = liferayPortletResponse.getNamespace() + "selectSite";

	ItemSelector itemSelector = (ItemSelector)request.getAttribute(SiteAdministrationWebKeys.ITEM_SELECTOR);

	GroupItemSelectorCriterion groupItemSelectorCriterion = new GroupItemSelectorCriterion();

	groupItemSelectorCriterion.setDesiredItemSelectorReturnTypes(new URLItemSelectorReturnType());
	groupItemSelectorCriterion.setIncludeAllVisibleGroups(true);

	PortletURL itemSelectorURL = itemSelector.getItemSelectorURL(RequestBackedPortletURLFactoryUtil.create(liferayPortletRequest), eventName, groupItemSelectorCriterion);
	%>

	<script>
		(function () {
			var manageSitesLink = document.getElementById(
				'<portlet:namespace />manageSitesLink'
			);

			if (manageSitesLink) {
				manageSitesLink.addEventListener('click', function (event) {
					Liferay.Util.openModal({
						id: '<portlet:namespace />selectSite',
						onSelect: function (selectedItem) {
							Liferay.Util.navigate(selectedItem.url);
						},
						selectEventName: '<%= eventName %>',
						title:
							'<liferay-ui:message key="select-site-or-asset-library" />',
						url: '<%= itemSelectorURL.toString() %>',
					});
				});
			}
		})();
	</script>
</c:if>

<c:choose>
	<c:when test="<%= group != null %>">
		<a aria-controls="<portlet:namespace /><%= AUIUtil.normalizeId(panelCategory.getKey()) %>Collapse" aria-expanded="<%= siteAdministrationPanelCategoryDisplayContext.isCollapsedPanel() %>" class="panel-toggler <%= (group != null) ? "collapse-icon collapse-icon-middle " : StringPool.BLANK %> <%= siteAdministrationPanelCategoryDisplayContext.isCollapsedPanel() ? StringPool.BLANK : "collapsed" %> site-administration-toggler" data-parent="#<portlet:namespace />Accordion" data-qa-id="productMenuSiteAdministrationPanelCategory" data-toggle="liferay-collapse" href="#<portlet:namespace /><%= AUIUtil.normalizeId(panelCategory.getKey()) %>Collapse" id="<portlet:namespace /><%= AUIUtil.normalizeId(panelCategory.getKey()) %>Toggler" <%= (group != null) ? "role=\"button\"" : StringPool.BLANK %>>
			<div class="autofit-row autofit-row-center">
				<div class="autofit-col">
					<c:choose>
						<c:when test="<%= Validator.isNotNull(siteAdministrationPanelCategoryDisplayContext.getLogoURL()) %>">
							<div class="aspect-ratio-bg-cover sticker" style="background-image: url(<%= siteAdministrationPanelCategoryDisplayContext.getLogoURL() %>);"></div>
						</c:when>
						<c:otherwise>
							<clay:sticker
								displayType="secondary"
								icon="<%= group.getIconCssClass() %>"
							/>
						</c:otherwise>
					</c:choose>
				</div>

				<div class="autofit-col autofit-col-expand mr-4">
					<div class="depot-type">
						<liferay-ui:message key='<%= (group.getType() == GroupConstants.TYPE_DEPOT) ? "asset-library" : "site" %>' />
					</div>

					<div class="lfr-portal-tooltip site-name text-truncate" title="<%= HtmlUtil.escape(siteAdministrationPanelCategoryDisplayContext.getGroupName()) %>">
						<%= HtmlUtil.escape(siteAdministrationPanelCategoryDisplayContext.getGroupName()) %>

						<c:if test="<%= siteAdministrationPanelCategoryDisplayContext.isShowStagingInfo() && !group.isStagedRemotely() %>">
							<span class="site-sub-name"> - <liferay-ui:message key="<%= siteAdministrationPanelCategoryDisplayContext.getStagingLabel() %>" /></span>
						</c:if>
					</div>
				</div>
			</div>

			<c:if test="<%= siteAdministrationPanelCategoryDisplayContext.getNotificationsCount() > 0 %>">
				<clay:sticker
					cssClass="panel-notifications-count"
					displayType="warning"
					position="top-right"
					size="sm"
				>
					<%= siteAdministrationPanelCategoryDisplayContext.getNotificationsCount() %>
				</clay:sticker>
			</c:if>

			<aui:icon cssClass="collapse-icon-closed" image="angle-right" markupView="lexicon" />

			<aui:icon cssClass="collapse-icon-open" image="angle-down" markupView="lexicon" />
		</a>
	</c:when>
	<c:when test="<%= siteAdministrationPanelCategoryDisplayContext.isShowSiteSelector() %>">
		<div class="collapsed panel-toggler">
			<span class="site-name">
				<liferay-ui:message key="choose-a-site" />
			</span>
		</div>
	</c:when>
</c:choose>