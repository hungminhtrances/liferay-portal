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

import {cleanup, render} from '@testing-library/react';
import React from 'react';

import List from '../../../../src/main/resources/META-INF/resources/js/components/list/List.es';

const props = {
	data: ['label1', 'label2', 'label3', 'label4', 'label5'],
	onClick: () => {},
	totalEntries: 5,
};

describe('List', () => {
	afterEach(cleanup);

	it('renders', () => {
		const {asFragment, container} = render(<List {...props} />);

		const li = container.querySelectorAll('li');

		expect(li.length).toBe(5);

		expect(asFragment()).toMatchSnapshot();
	});

	it('shows a button to see all entries when there are more than 5 entries', () => {
		const {container} = render(<List {...props} totalEntries={6} />);

		expect(container.querySelector('button').innerHTML).toBe(
			'see-all-entries'
		);
	});
});
