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

import React, {useContext} from 'react';
import {Redirect} from 'react-router-dom';

import {AppContext} from '../../AppContext.es';
import NavigationBar from '../../components/navigation-bar/NavigationBar.es';
import useLazy from '../../hooks/useLazy.es';

export default (props) => {
	const {appsTabs, appsTabsKeys} = useContext(AppContext);
	const {tab} = props.match.params;

	if (!tab || !appsTabsKeys.includes(tab)) {
		const initialTabKey = appsTabsKeys[0] || 'standard';

		return <Redirect to={`/${initialTabKey}`} />;
	}

	const {listEntryPoint, ...otherProps} = appsTabs[tab];
	const navTabs = Object.values(appsTabs).map(({label, scope}) => ({
		active: tab === scope,
		label,
		path: () => `/${scope}`,
	}));
	const TabContent = useLazy();

	return (
		<>
			<NavigationBar tabs={navTabs} />

			<TabContent
				module={listEntryPoint}
				props={{...props, ...otherProps}}
			/>
		</>
	);
};
