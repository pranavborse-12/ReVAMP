import { useState } from "react";
import { Check, Zap } from "lucide-react";
import { Button } from "./ui/button";
import { CardBody, CardContainer, CardItem } from "./ui/3d-card"; // Assuming previous file exists
import { cn } from "../lib/utils";

const pricing = [
  {
    name: "Starter",
    price: "0",
    desc: "For hobbyists and side projects.",
    features: ["Scans up to 5 repositories", "OWASP Top 10 detection", "Community Support", "7-day history"],
    cta: "Start for Free",
    popular: false,
  },
  {
    name: "Pro Team",
    price: "49",
    desc: "For growing engineering teams.",
    features: ["Unlimited repositories", "CI/CD Integration", "AI Auto-fix PRs", "Priority Support", "Compliance Reports"],
    cta: "Start Trial",
    popular: true,
  },
  {
    name: "Enterprise",
    price: "Custom",
    desc: "For large organizations.",
    features: ["Self-hosted / On-prem", "Custom Rule Engine", "SLA Guarantee", "Dedicated Account Manager", "SSO / SAML"],
    cta: "Contact Sales",
    popular: false,
  },
];

export function Pricing() {
  const [isAnnual, setIsAnnual] = useState(true);

  return (
    <section id="pricing" className="py-24 bg-black relative">
      <div className="absolute inset-0 bg-[linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:40px_40px]"></div>
      
      <div className="container max-w-7xl mx-auto px-6 relative z-10">
        <div className="text-center mb-16 space-y-4">
          <h2 className="text-3xl md:text-5xl font-bold text-white">
            Simple, transparent <span className="text-blue-500">pricing</span>
          </h2>
          <div className="flex items-center justify-center gap-4 pt-4">
            <span className={cn("text-sm", !isAnnual ? "text-white" : "text-zinc-500")}>Monthly</span>
            <button 
              onClick={() => setIsAnnual(!isAnnual)}
              className="w-12 h-6 rounded-full bg-zinc-800 border border-zinc-700 relative transition-colors"
            >
              <div className={cn(
                "absolute top-1 w-4 h-4 rounded-full bg-blue-500 transition-all duration-300",
                isAnnual ? "left-7" : "left-1"
              )} />
            </button>
            <span className={cn("text-sm", isAnnual ? "text-white" : "text-zinc-500")}>
              Yearly <span className="text-emerald-500 text-xs ml-1 font-bold">(-20%)</span>
            </span>
          </div>
        </div>

        <div className="grid md:grid-cols-3 gap-8">
          {pricing.map((tier, i) => (
            <CardContainer key={i} className="inter-var">
              <CardBody className={cn(
                "bg-zinc-900/50 relative group/card border-black/[0.1] w-full h-auto rounded-xl p-8 border transition-all duration-300 hover:shadow-2xl hover:shadow-blue-500/10",
                tier.popular ? "border-blue-500/50 bg-zinc-900/80" : "border-white/[0.1]"
              )}>
                {tier.popular && (
                  <div className="absolute -top-4 left-0 right-0 flex justify-center">
                    <div className="bg-gradient-to-r from-blue-600 to-cyan-600 text-white text-xs font-bold px-3 py-1 rounded-full shadow-lg flex items-center gap-1">
                      <Zap className="w-3 h-3 fill-white" /> Most Popular
                    </div>
                  </div>
                )}

                <CardItem translateZ="50" className="text-xl font-bold text-white">
                  {tier.name}
                </CardItem>
                
                <CardItem translateZ="60" className="my-4">
                  <span className="text-4xl font-bold text-white">
                    {tier.price === "Custom" ? "Custom" : `$${isAnnual ? tier.price : parseInt(tier.price) * 1.2}`}
                  </span>
                  {tier.price !== "Custom" && <span className="text-zinc-500">/mo</span>}
                </CardItem>
                
                <CardItem translateZ="40" className="text-zinc-400 text-sm mb-8">
                  {tier.desc}
                </CardItem>

                <div className="space-y-4 mb-8">
                  {tier.features.map((feat, idx) => (
                    <CardItem key={idx} translateZ="30" className="flex items-center gap-3 text-sm text-zinc-300">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" />
                      {feat}
                    </CardItem>
                  ))}
                </div>

                <CardItem translateZ="80" className="w-full">
                  <Button 
                    className={cn(
                      "w-full h-12 font-bold",
                      tier.popular ? "bg-blue-600 hover:bg-blue-500 shadow-lg shadow-blue-500/25" : "bg-white text-black hover:bg-zinc-200"
                    )}
                  >
                    {tier.cta}
                  </Button>
                </CardItem>
              </CardBody>
            </CardContainer>
          ))}
        </div>
      </div>
    </section>
  );
}