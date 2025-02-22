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

package com.liferay.headless.delivery.internal.resource.v1_0;

import com.liferay.headless.common.spi.service.context.ServiceContextUtil;
import com.liferay.headless.delivery.dto.v1_0.NavigationMenu;
import com.liferay.headless.delivery.dto.v1_0.NavigationMenuItem;
import com.liferay.headless.delivery.internal.dto.v1_0.util.CreatorUtil;
import com.liferay.headless.delivery.resource.v1_0.NavigationMenuResource;
import com.liferay.portal.kernel.model.Layout;
import com.liferay.portal.kernel.service.LayoutLocalService;
import com.liferay.portal.kernel.service.UserLocalService;
import com.liferay.portal.kernel.util.GetterUtil;
import com.liferay.portal.kernel.util.HashMapBuilder;
import com.liferay.portal.kernel.util.LocaleUtil;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.StringUtil;
import com.liferay.portal.kernel.util.UnicodeProperties;
import com.liferay.portal.vulcan.pagination.Page;
import com.liferay.portal.vulcan.pagination.Pagination;
import com.liferay.portal.vulcan.util.LocalizedMapUtil;
import com.liferay.site.navigation.constants.SiteNavigationConstants;
import com.liferay.site.navigation.model.SiteNavigationMenu;
import com.liferay.site.navigation.model.SiteNavigationMenuItem;
import com.liferay.site.navigation.service.SiteNavigationMenuItemService;
import com.liferay.site.navigation.service.SiteNavigationMenuService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ServiceScope;

/**
 * @author Javier Gamarra
 */
@Component(
	properties = "OSGI-INF/liferay/rest/v1_0/navigation-menu.properties",
	scope = ServiceScope.PROTOTYPE, service = NavigationMenuResource.class
)
public class NavigationMenuResourceImpl extends BaseNavigationMenuResourceImpl {

	@Override
	public void deleteNavigationMenu(Long navigationMenuId) throws Exception {
		_siteNavigationMenuService.deleteSiteNavigationMenu(navigationMenuId);
	}

	@Override
	public NavigationMenu getNavigationMenu(Long navigationMenuId)
		throws Exception {

		return _toNavigationMenu(
			_siteNavigationMenuService.fetchSiteNavigationMenu(
				navigationMenuId));
	}

	@Override
	public Page<NavigationMenu> getSiteNavigationMenusPage(
		Long siteId, Pagination pagination) {

		return Page.of(
			Collections.singletonMap(
				"create",
				addAction(
					"ADD_SITE_NAVIGATION_MENU", "postSiteNavigationMenu",
					"com.liferay.site.navigation", siteId)),
			transform(
				_siteNavigationMenuService.getSiteNavigationMenus(
					siteId, pagination.getStartPosition(),
					pagination.getEndPosition(), null),
				this::_toNavigationMenu),
			pagination,
			_siteNavigationMenuService.getSiteNavigationMenusCount(siteId));
	}

	@Override
	public NavigationMenu postSiteNavigationMenu(
			Long siteId, NavigationMenu navigationMenu)
		throws Exception {

		SiteNavigationMenu siteNavigationMenu =
			_siteNavigationMenuService.addSiteNavigationMenu(
				siteId, navigationMenu.getName(),
				SiteNavigationConstants.TYPE_DEFAULT, true,
				ServiceContextUtil.createServiceContext(siteId, null));

		_createNavigationMenuItems(
			navigationMenu.getNavigationMenuItems(), 0, siteId,
			siteNavigationMenu.getSiteNavigationMenuId());

		return _toNavigationMenu(siteNavigationMenu);
	}

	@Override
	public NavigationMenu putNavigationMenu(
			Long navigationMenuId, NavigationMenu navigationMenu)
		throws Exception {

		SiteNavigationMenu siteNavigationMenu =
			_siteNavigationMenuService.fetchSiteNavigationMenu(
				navigationMenuId);

		_updateNavigationMenuItems(
			navigationMenu.getNavigationMenuItems(), 0,
			siteNavigationMenu.getGroupId(),
			siteNavigationMenu.getSiteNavigationMenuId());

		return _toNavigationMenu(
			_siteNavigationMenuService.updateSiteNavigationMenu(
				navigationMenuId, navigationMenu.getName(),
				ServiceContextUtil.createServiceContext(
					siteNavigationMenu.getGroupId(), null)));
	}

	private void _createNavigationMenuItem(
			NavigationMenuItem navigationMenuItem, long parentNavigationMenuId,
			long siteId, long siteNavigationMenuId)
		throws Exception {

		String unicodeProperties = _getUnicodeProperties(
			true, navigationMenuItem, siteId);

		SiteNavigationMenuItem siteNavigationMenuItem =
			_siteNavigationMenuItemService.addSiteNavigationMenuItem(
				siteId, siteNavigationMenuId, parentNavigationMenuId,
				_getType(navigationMenuItem), unicodeProperties,
				ServiceContextUtil.createServiceContext(siteId, null));

		_createNavigationMenuItems(
			navigationMenuItem.getNavigationMenuItems(),
			siteNavigationMenuItem.getSiteNavigationMenuItemId(), siteId,
			siteNavigationMenuId);
	}

	private void _createNavigationMenuItems(
			NavigationMenuItem[] navigationMenuItems,
			long parentNavigationMenuId, long siteId, long siteNavigationMenuId)
		throws Exception {

		if (navigationMenuItems == null) {
			return;
		}

		for (NavigationMenuItem navigationMenuItem : navigationMenuItems) {
			_createNavigationMenuItem(
				navigationMenuItem, parentNavigationMenuId, siteId,
				siteNavigationMenuId);
		}
	}

	private Layout _getLayout(SiteNavigationMenuItem siteNavigationMenuItem) {
		UnicodeProperties typeSettingsUnicodeProperties =
			new UnicodeProperties();

		typeSettingsUnicodeProperties.fastLoad(
			siteNavigationMenuItem.getTypeSettings());

		String layoutUuid = typeSettingsUnicodeProperties.get("layoutUuid");
		boolean privateLayout = GetterUtil.getBoolean(
			typeSettingsUnicodeProperties.get("privateLayout"));

		return _layoutLocalService.fetchLayoutByUuidAndGroupId(
			layoutUuid, siteNavigationMenuItem.getGroupId(), privateLayout);
	}

	private Layout _getLayout(String link, long siteId) throws Exception {
		Layout layout = _layoutLocalService.fetchLayoutByFriendlyURL(
			siteId, false, link);

		if (layout == null) {
			layout = _layoutLocalService.getLayoutByFriendlyURL(
				siteId, true, link);
		}

		return layout;
	}

	private Locale _getLocaleFromProperty(Map.Entry<String, String> property) {
		return LocaleUtil.fromLanguageId(
			StringUtil.removeSubstring(property.getKey(), "name_"));
	}

	private Map<Locale, String> _getLocalizedNamesFromProperties(
		UnicodeProperties typeSettingsUnicodeProperties) {

		Set<Map.Entry<String, String>> properties =
			typeSettingsUnicodeProperties.entrySet();

		Stream<Map.Entry<String, String>> propertiesStream =
			properties.stream();

		return propertiesStream.filter(
			this::_isNameProperty
		).collect(
			Collectors.toMap(this::_getLocaleFromProperty, Map.Entry::getValue)
		);
	}

	private Map<Long, List<SiteNavigationMenuItem>>
		_getSiteNavigationMenuItemsMap(
			List<SiteNavigationMenuItem> siteNavigationMenuItems) {

		Map<Long, List<SiteNavigationMenuItem>> siteNavigationMenuItemsMap =
			new HashMap<>();

		for (SiteNavigationMenuItem siteNavigationMenuItem :
				siteNavigationMenuItems) {

			long parentSiteNavigationMenuItemId =
				siteNavigationMenuItem.getParentSiteNavigationMenuItemId();

			if (siteNavigationMenuItemsMap.containsKey(
					parentSiteNavigationMenuItemId)) {

				continue;
			}

			for (SiteNavigationMenuItem childSiteNavigationMenuItem :
					siteNavigationMenuItems) {

				if (parentSiteNavigationMenuItemId !=
						childSiteNavigationMenuItem.
							getParentSiteNavigationMenuItemId()) {

					continue;
				}

				List<SiteNavigationMenuItem> parentSiteNavigationMenuItems =
					siteNavigationMenuItemsMap.getOrDefault(
						parentSiteNavigationMenuItemId, new ArrayList<>());

				parentSiteNavigationMenuItems.add(childSiteNavigationMenuItem);

				siteNavigationMenuItemsMap.put(
					parentSiteNavigationMenuItemId,
					parentSiteNavigationMenuItems);
			}
		}

		return siteNavigationMenuItemsMap;
	}

	private String _getType(NavigationMenuItem navigationMenuItem) {
		if (navigationMenuItem.getLink() != null) {
			return "layout";
		}
		else if (navigationMenuItem.getUrl() != null) {
			return "url";
		}

		return "node";
	}

	private String _getUnicodeProperties(
			boolean add, NavigationMenuItem navigationMenuItem, long siteId)
		throws Exception {

		UnicodeProperties unicodeProperties = new UnicodeProperties(true);

		if (navigationMenuItem.getLink() != null) {
			Layout layout = _getLayout(navigationMenuItem.getLink(), siteId);

			unicodeProperties.setProperty(
				"groupId", String.valueOf(layout.getGroupId()));
			unicodeProperties.setProperty("layoutUuid", layout.getUuid());
			unicodeProperties.setProperty(
				"name", layout.getName(LocaleUtil.getDefault()));
			unicodeProperties.setProperty(
				"privateLayout", String.valueOf(layout.isPrivateLayout()));
		}
		else {
			Map<Locale, String> nameMap = LocalizedMapUtil.getLocalizedMap(
				contextAcceptLanguage.getPreferredLocale(),
				navigationMenuItem.getName(),
				navigationMenuItem.getName_i18n());

			LocalizedMapUtil.validateI18n(
				add, LocaleUtil.getSiteDefault(), "Navigation Menu item",
				nameMap, new HashSet<>());

			unicodeProperties.setProperty(
				"defaultLanguageId",
				LocaleUtil.toLanguageId(LocaleUtil.getDefault()));

			for (Map.Entry<Locale, String> entry : nameMap.entrySet()) {
				unicodeProperties.setProperty(
					"name_" + LocaleUtil.toLanguageId(entry.getKey()),
					nameMap.get(entry.getKey()));
			}

			if (navigationMenuItem.getUrl() != null) {
				unicodeProperties.setProperty(
					"url", navigationMenuItem.getUrl());
			}
		}

		return unicodeProperties.toString();
	}

	private boolean _isNameProperty(Map.Entry<String, String> property) {
		String propertyKey = property.getKey();

		return propertyKey.startsWith("name_");
	}

	private NavigationMenu _toNavigationMenu(
		SiteNavigationMenu siteNavigationMenu) {

		List<SiteNavigationMenuItem> siteNavigationMenuItems =
			_siteNavigationMenuItemService.getSiteNavigationMenuItems(
				siteNavigationMenu.getSiteNavigationMenuId());

		Map<Long, List<SiteNavigationMenuItem>> siteNavigationMenuItemsMap =
			_getSiteNavigationMenuItemsMap(siteNavigationMenuItems);

		return new NavigationMenu() {
			{
				creator = CreatorUtil.toCreator(
					_portal,
					_userLocalService.fetchUser(
						siteNavigationMenu.getUserId()));
				dateCreated = siteNavigationMenu.getCreateDate();
				dateModified = siteNavigationMenu.getModifiedDate();
				id = siteNavigationMenu.getSiteNavigationMenuId();
				name = siteNavigationMenu.getName();
				navigationMenuItems = transformToArray(
					siteNavigationMenuItemsMap.getOrDefault(
						0L, new ArrayList<>()),
					siteNavigationMenuItem -> _toNavigationMenuItem(
						siteNavigationMenuItem, siteNavigationMenuItemsMap),
					NavigationMenuItem.class);
				siteId = siteNavigationMenu.getGroupId();

				setActions(
					() -> HashMapBuilder.put(
						"delete",
						addAction(
							"DELETE", siteNavigationMenu,
							"deleteNavigationMenu")
					).put(
						"replace",
						addAction(
							"UPDATE", siteNavigationMenu, "putNavigationMenu")
					).build());
			}
		};
	}

	private NavigationMenuItem _toNavigationMenuItem(
		SiteNavigationMenuItem siteNavigationMenuItem,
		Map<Long, List<SiteNavigationMenuItem>> siteNavigationMenuItemsMap) {

		UnicodeProperties typeSettingsUnicodeProperties =
			new UnicodeProperties();

		typeSettingsUnicodeProperties.fastLoad(
			siteNavigationMenuItem.getTypeSettings());

		Layout layout = _getLayout(siteNavigationMenuItem);

		return new NavigationMenuItem() {
			{
				creator = CreatorUtil.toCreator(
					_portal,
					_userLocalService.fetchUser(
						siteNavigationMenuItem.getUserId()));
				dateCreated = siteNavigationMenuItem.getCreateDate();
				dateModified = siteNavigationMenuItem.getModifiedDate();
				id = siteNavigationMenuItem.getSiteNavigationMenuItemId();
				navigationMenuItems = transformToArray(
					siteNavigationMenuItemsMap.getOrDefault(
						siteNavigationMenuItem.getSiteNavigationMenuItemId(),
						new ArrayList<>()),
					item -> _toNavigationMenuItem(
						item, siteNavigationMenuItemsMap),
					NavigationMenuItem.class);
				type = _toType(siteNavigationMenuItem.getType());
				url = typeSettingsUnicodeProperties.getProperty("url");

				setLink(
					() -> {
						if (layout == null) {
							return null;
						}

						return layout.getFriendlyURL();
					});
				setName(
					() -> {
						String preferredLanguageId =
							contextAcceptLanguage.getPreferredLanguageId();
						String defaultLanguageId = LocaleUtil.toLanguageId(
							LocaleUtil.getDefault());

						String name = typeSettingsUnicodeProperties.getProperty(
							"name_" + preferredLanguageId,
							typeSettingsUnicodeProperties.getProperty(
								"name_" + defaultLanguageId));

						if ((name == null) && (layout != null)) {
							name = layout.getName(
								contextAcceptLanguage.getPreferredLocale());
						}

						return name;
					});
				setName_i18n(
					() -> {
						if (contextAcceptLanguage.isAcceptAllLanguages()) {
							Map<Locale, String> localizedNames =
								_getLocalizedNamesFromProperties(
									typeSettingsUnicodeProperties);

							if (localizedNames.isEmpty() && (layout != null)) {
								localizedNames = layout.getNameMap();
							}

							return LocalizedMapUtil.getI18nMap(
								true, localizedNames);
						}

						return null;
					});
			}
		};
	}

	private String _toType(String type) {
		if (type.equals("layout")) {
			return "page";
		}
		else if (type.equals("node")) {
			return "navigationMenu";
		}

		return type;
	}

	private void _updateNavigationMenuItems(
			NavigationMenuItem[] navigationMenuItems,
			long parentSiteNavigationMenuId, Long siteId,
			long siteNavigationMenuId)
		throws Exception {

		List<SiteNavigationMenuItem> siteNavigationMenuItems = new ArrayList<>(
			_siteNavigationMenuItemService.getSiteNavigationMenuItems(
				siteNavigationMenuId, parentSiteNavigationMenuId));

		if (navigationMenuItems != null) {
			for (NavigationMenuItem navigationMenuItem : navigationMenuItems) {
				Stream<SiteNavigationMenuItem> stream =
					siteNavigationMenuItems.stream();

				Long navigationMenuItemId = navigationMenuItem.getId();

				Optional<SiteNavigationMenuItem>
					siteNavigationMenuItemOptional = stream.filter(
						siteNavigationMenuItem -> Objects.equals(
							siteNavigationMenuItem.
								getSiteNavigationMenuItemId(),
							navigationMenuItemId)
					).findFirst();

				if (siteNavigationMenuItemOptional.isPresent()) {
					SiteNavigationMenuItem siteNavigationMenuItem =
						_siteNavigationMenuItemService.
							updateSiteNavigationMenuItem(
								navigationMenuItemId,
								_getUnicodeProperties(
									false, navigationMenuItem, siteId),
								ServiceContextUtil.createServiceContext(
									siteId, null));

					_updateNavigationMenuItems(
						navigationMenuItem.getNavigationMenuItems(),
						siteNavigationMenuItem.getSiteNavigationMenuItemId(),
						siteId, siteNavigationMenuId);

					siteNavigationMenuItems.remove(
						siteNavigationMenuItemOptional.get());
				}
				else {
					_createNavigationMenuItem(
						navigationMenuItem, parentSiteNavigationMenuId, siteId,
						siteNavigationMenuId);
				}
			}
		}

		for (SiteNavigationMenuItem siteNavigationMenuItem :
				siteNavigationMenuItems) {

			_siteNavigationMenuItemService.deleteSiteNavigationMenuItem(
				siteNavigationMenuItem.getSiteNavigationMenuItemId());
		}
	}

	@Reference
	private LayoutLocalService _layoutLocalService;

	@Reference
	private Portal _portal;

	@Reference
	private SiteNavigationMenuItemService _siteNavigationMenuItemService;

	@Reference
	private SiteNavigationMenuService _siteNavigationMenuService;

	@Reference
	private UserLocalService _userLocalService;

}