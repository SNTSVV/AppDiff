/*
 * Copyright (c) 2015-2018  Erik Derr [derr@cs.uni-saarland.de]
 * Copyright (c) 2018-2019  Erik Derr,  University of Luxembourg [erik.derr@uni.lu]
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package de.infsec.tpl.utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

public class MathUtils {
	
	public static float computePercentage(int first, int second) {
		if (second == 0)
			return Float.NaN;
		else
			return (float) Math.round((Float.intBitsToFloat(first) / Float.intBitsToFloat(second)) * 100 * 100) / 100;
	}

	public static double computePercentage(long first, long second) {
		if (second == 0)
			return Double.NaN;
		else
			return (double) Math.round((Double.longBitsToDouble(first) / Double.longBitsToDouble(second)) * 100 * 100) / 100;
	}

	public static float round(float number, int digits) {
		return Math.round(number * ((float) Math.pow(10, digits))) / ((float)Math.pow(10, digits));
	}
	public static double round(double number, int digits) {
		return Math.round(number * Math.pow(10, digits)) / Math.pow(10, digits);
	}
	

	public static double average(Collection<Float> values) {
		Float sum = 0.f;
		if (!values.isEmpty()) {
			for (Float val : values) {
		        sum += val;
		    }
		    
			return sum.doubleValue() / values.size();
		}
			return sum;
	}

	public static double median(Collection<Float> values) {
		if (values.isEmpty())
			return Double.NaN;
		
		ArrayList<Float> sortedValues = new ArrayList<Float>(values);
		Collections.sort(sortedValues);
		
	    int middle = sortedValues.size()/2;
	    if (sortedValues.size() %2 == 1) {
	        return sortedValues.get(middle);
	    } else {
	        return (sortedValues.get(middle-1) + sortedValues.get(middle)) / 2.0;
	    }
	}
	
	// TODO REWORK
	public static double medianInt(Collection<Integer> values) {
		if (values.isEmpty())
			return Double.NaN;
		
		ArrayList<Integer> sortedValues = new ArrayList<Integer>(values);
		Collections.sort(sortedValues);
		
	    int middle = sortedValues.size()/2;
	    if (sortedValues.size() %2 == 1) {
	        return sortedValues.get(middle);
	    } else {
	        return (sortedValues.get(middle-1) + sortedValues.get(middle)) / 2.0;
	    }
	}
}
