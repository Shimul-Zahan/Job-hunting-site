import Lottie from "lottie-react";
import aboutUs from "../../../public/aboutUs.json"
import { MdOutlineWork, MdSecurity } from "react-icons/md";

const AboutUs = () => {
    return (
        <div className="lg:w-3/4 w-11/12 mx-auto py-16">
            <h2 className="text-5xl font-semibold text-center pt-3 pb-6">About Us</h2>
            <div>
                <div className="flex justify-between">
                    <div>
                        <h3 className="text-4xl font-semibold pb-3">Speech from Founder</h3>
                        <div className="font-semibold pb-3">
                            <h4>Airon Mark Ramirez</h4>
                            <h5>Operating Officer</h5>
                        </div>
                    </div>
                    <div className="w-1/6 hidden md:block">
                        <Lottie animationData={aboutUs} />
                    </div>
                </div>
                <p className="pb-4 text-justify">My professional journey took flight in the vibrant sectors of Business Process Outsourcing (BPO), Recruitment Process Outsourcing (RPO), and Knowledge Process Outsourcing (KPO). Starting as an HR analyst in a top-tier outsourcing firm, I was not just a licensed teacher but also a Latin honor graduate from a prestigious university in the Philippines. This role served as a launchpad, enabling me to dive deep into the realm of global talent sourcing, working alongside Fortune 500 companies and major tech firms.</p>
                <p className="text-justify">This hands-on experience sharpened my skills in aligning employers with the ideal talent, and I identified a need in the market for a more efficient recruitment solution. This realization led to the inception of airTalX. My mission is clear and impactful: to revolutionize how companies discover and recruit top-tier talent within the BPO, RPO, and KPO sectors. With airTalX, I am committed to making the recruitment process more streamlined, effective, and accessible for all.
                    Our Actions Reflect Our Words!
                </p>
            </div>
            <div className="bg-[#2792a8] text-white my-12 rounded-md">
                <h1 className="text-6xl text-center py-8">airtalx: Your Trusted Platform for Online Jobs in the Philippines</h1>
            </div>
            <div className="">
                <h3 className="text-4xl font-semibold pb-3">Our Motive</h3>
                <p className="text-justify">We're not just talk, we're about action. Our team is a testament to this, with a significant portion of our workforce hailing directly from the Philippines. Even our top executives, including our Leader and Manager, are proud products of the Philippines, born and bred. We believe in the talent and potential that the Philippines has to offer, and we're committed to nurturing it.</p>
            </div>
            <div className="grid lg:grid-cols-2 grid-cols-1 gap-5">
                <div className="my-12 flex gap-3 custom-shadow px-3 py-5 pr-9">
                    <div>
                        <MdSecurity className="text-[200px] text-[#2792a8]" />
                    </div>
                    <div>
                        <p className="text-justify">At airtalx, we prioritize the safety and satisfaction of our job seekers. We're proud to be recognized as the most reliable platform for securing long-term online jobs in the Philippines.</p>
                    </div>
                </div>
                <div className="my-12 flex gap-3 custom-shadow px-3 py-5 pr-9">
                    <div>
                        <MdOutlineWork className="text-[200px] text-[#2792a8]" />
                    </div>
                    <div>
                        <p className="text-justify">Whether you're seeking part-time work or a full-time career, airtalx offers a wealth of opportunities. With thousands of jobs posted daily, you're sure to find the perfect fit for your skills and schedule. Start your journey with airtalx today!
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AboutUs;