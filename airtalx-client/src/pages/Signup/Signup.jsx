import { useState } from 'react';
import EmployerSignup from './Components/EmployerSignup';
import JobseekerSignup from './Components/JobseekerSignup';

const Signup = () => {
    const [activeTab, setActiveTab] = useState(0);

    return (
        <div className="lg:w-1/2 w-11/12 mx-auto lg:my-28 my-12">
            <div className="text-center pb-6">
                <h1 className="text-5xl pb-2 font-bold">Get Started</h1>
                <p className="text-lg font-semibold">In our website you can signup either as an employer or a jobseeker.</p>
            </div>
            <div className="flex justify-center gap-8">
                <button
                    className={`cursor-pointer text-2xl font-semibold focus:outline-none ${activeTab === 0 ? 'text-[#1d9cb5]' : 'text-gray-500'}`}
                    onClick={() => setActiveTab(0)}
                >
                    I want to hire
                </button>
                <button
                    className={`cursor-pointer text-2xl font-semibold focus:outline-none ${activeTab === 1 ? 'text-[#1d9cb5]' : 'text-gray-500'}`}
                    onClick={() => setActiveTab(1)}
                >
                    I want a job
                </button>
            </div>
            {activeTab === 0 ? <EmployerSignup /> : <JobseekerSignup />}
        </div>
    );
};

export default Signup;
